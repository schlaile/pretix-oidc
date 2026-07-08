import logging
import time
from configparser import NoOptionError, NoSectionError
from django.urls import reverse
from oic import rndstr
from oic.oic import Client
from oic.oic.message import (
    AuthorizationResponse,
    ProviderConfigurationResponse,
    RegistrationResponse,
)
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from pretix.base.auth import BaseAuthBackend
from pretix.settings import config

from .assignment import claims_dict, is_error_response, pick_claim
from .linking import persist_session

logger = logging.getLogger(__name__)

OIDC_STATE_TTL = 5 * 60


class OIDCAuthBackend(BaseAuthBackend):
    def __init__(self):
        try:
            self.title = config.get(
                "oidc", "title", fallback="Login with OpenID connect"
            )

            op_info = ProviderConfigurationResponse(
                version="1.0",
                issuer=config.get("oidc", "issuer"),
                authorization_endpoint=config.get("oidc", "authorization_endpoint"),
                token_endpoint=config.get("oidc", "token_endpoint"),
                userinfo_endpoint=config.get("oidc", "userinfo_endpoint"),
                end_session_endpoint=config.get("oidc", "end_session_endpoint"),
                jwks_uri=config.get("oidc", "jwks_uri"),
            )

            client_reg = RegistrationResponse(
                client_id=config.get("oidc", "client_id"),
                client_secret=config.get("oidc", "client_secret"),
            )

            self.client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
            self.client.handle_provider_config(op_info, op_info["issuer"])
            self.client.store_registration_info(client_reg)
            self.client.redirect_uris = [None]

            self.scopes = [
                s.strip()
                for s in config.get("oidc", "scopes", fallback="openid").split(",")
                if s.strip()
            ]
        except (NoSectionError, NoOptionError):
            logger.error(
                "Please specify issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, end_session_endpoint, jwks_uri, client_id and client_secret "
                "in [oidc] section in pretix.cfg"
            )

    @property
    def identifier(self):
        return "pretix_oidc"

    @property
    def verbose_name(self):
        return self.title

    def _fresh_oidc_states(self, request):
        now = int(time.time())
        states = dict(request.session.get("oidc_state") or {})
        return {
            key: value
            for key, value in states.items()
            if value.get("generated_on", 0) >= now - OIDC_STATE_TTL
        }

    def _remember_oidc_state(self, request, state, data):
        states = self._fresh_oidc_states(request)
        states[state] = data
        request.session["oidc_state"] = states
        persist_session(request)

    def _callback_fail(self, request, reason):
        logger.warning("OIDC callback failed: %s", reason)
        request.session["oidc_callback_error"] = reason
        persist_session(request)
        return [None, None, None]

    def authentication_url(self, request, purpose="login", link_user_id=None):
        oidc_state = rndstr()
        self._remember_oidc_state(
            request,
            oidc_state,
            {
                "next": request.GET.get("next", None),
                "generated_on": int(time.time()),
                "purpose": purpose,
                "link_user_id": link_user_id,
            },
        )

        auth_req = self.client.construct_AuthorizationRequest(
            request_args={
                "client_id": self.client.client_id,
                "response_type": "code",
                "scope": self.scopes,
                "redirect_uri": self.redirect_uri(request),
                "state": oidc_state,
            }
        )

        return auth_req.request(self.client.authorization_endpoint)

    def redirect_uri(self, request):
        return request.build_absolute_uri(reverse("plugins:pretix_oidc:oidc_callback"))

    def get_next_url(self, request):
        return request.session.pop("oidc_next_url", None)

    def process_callback(self, request):
        auth_response = self.client.parse_response(
            AuthorizationResponse,
            info=request.META["QUERY_STRING"],
            sformat="urlencoded",
        )

        request.session["oidc_next_url"] = None
        response_state = auth_response.get("state", None)
        states = self._fresh_oidc_states(request)

        if not states or not response_state:
            request.session["oidc_state"] = states
            return self._callback_fail(request, "state_missing")

        if response_state not in states:
            request.session["oidc_state"] = states
            return self._callback_fail(request, "state_mismatch")

        state_data = states.pop(response_state)
        request.session["oidc_state"] = states

        if state_data["generated_on"] < time.time() - OIDC_STATE_TTL:
            return self._callback_fail(request, "state_expired")

        request.session["oidc_callback_meta"] = {
            "purpose": state_data.get("purpose", "login"),
            "link_user_id": state_data.get("link_user_id"),
        }
        request.session["oidc_next_url"] = state_data["next"]

        try:
            access_token_response = self.client.do_access_token_request(
                state=auth_response["state"],
                scope=self.scopes,
                request_args={
                    "code": auth_response["code"],
                    "redirect_uri": self.redirect_uri(request),
                },
                authn_method="client_secret_basic",
            )
        except Exception:
            logger.exception("OIDC access token request failed")
            return self._callback_fail(request, "token_request")

        token_response = claims_dict(access_token_response)
        if token_response.get("error"):
            logger.warning(
                "OIDC access token response error: %s", token_response["error"]
            )
            return self._callback_fail(request, "token_error")

        try:
            userinfo = self.client.do_user_info_request(state=auth_response["state"])
        except Exception:
            logger.warning(
                "OIDC userinfo request failed; using id_token claims only",
                exc_info=True,
            )
            userinfo = None

        id_token = access_token_response.get("id_token")
        if id_token is None:
            return self._callback_fail(request, "missing_id_token")

        if is_error_response(userinfo):
            logger.warning(
                "OIDC userinfo response error: %s",
                claims_dict(userinfo).get("error"),
            )
            userinfo = None

        unique_attribute = config.get("oidc", "unique_attribute", fallback="sub")
        claim_sources = [id_token, userinfo]
        uuid = pick_claim(claim_sources, unique_attribute)
        email = pick_claim(claim_sources, "email")
        fullname = pick_claim(claim_sources, "name")
        email_verified = pick_claim(claim_sources, "email_verified")

        if not uuid or not email:
            logger.warning(
                "OIDC callback missing required claims: %s=%r email=%r",
                unique_attribute,
                uuid,
                email,
            )
            return self._callback_fail(request, "missing_claims")

        user_data = {
            "uuid": uuid,
            "email": email,
            "fullname": fullname,
            "email_verified": email_verified,
            "auth_backend": self.identifier,
        }

        request.session.pop("oidc_callback_error", None)
        return [user_data, claims_dict(id_token), claims_dict(userinfo)]
