import hashlib
import logging
import time
from configparser import NoOptionError, NoSectionError
from urllib.parse import quote
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
OIDC_REPLAY_SESSION_KEY = "oidc_code_replay"
TERMINAL_REPLAY_STATUSES = ("ok", "error", "native", "redirect")


def code_replay_key(code):
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def fresh_code_replays(request):
    now = int(time.time())
    replays = dict(request.session.get(OIDC_REPLAY_SESSION_KEY) or {})
    return {
        key: value
        for key, value in replays.items()
        if value.get("generated_on", 0) >= now - OIDC_STATE_TTL
    }


def get_code_replay(request, code):
    if not code:
        return None
    return fresh_code_replays(request).get(code_replay_key(code))


def store_code_replay(request, code, **fields):
    """Remember a callback outcome so a reload does not redeem the code again.

    Terminal outcomes stick. A later failure must not replace a success.
    """
    if not code:
        return None
    existing = get_code_replay(request, code)
    if existing and existing.get("status") in TERMINAL_REPLAY_STATUSES:
        return existing
    replays = fresh_code_replays(request)
    replay = {"generated_on": int(time.time()), **fields}
    replays[code_replay_key(code)] = replay
    request.session[OIDC_REPLAY_SESSION_KEY] = replays
    persist_session(request)
    return replay


def claim_code_for_exchange(code):
    """Return False when another request is already redeeming this code.

    The marker lives in the shared cache, not in an eager session.save().
    Saving the session mid-request races with the 2FA step and can drop
    pretix_auth_2fa_user. Without Redis or memcached the lock is skipped
    and a later reload still follows the session outcome.
    """
    if not code:
        return True
    from django.conf import settings

    if not getattr(settings, "REAL_CACHE_USED", False):
        return True
    from django.core.cache import cache

    try:
        return cache.add("pretix_oidc:code:" + code_replay_key(code), 1, OIDC_STATE_TTL)
    except Exception:
        logger.warning("OIDC code lock unavailable", exc_info=True)
        return True


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

    def _callback_fail(self, request, reason, code=None):
        logger.warning("OIDC callback failed: %s", reason)
        existing = get_code_replay(request, code)
        if existing and existing.get("status") in TERMINAL_REPLAY_STATUSES:
            if existing.get("status") == "error" and existing.get("reason"):
                request.session["oidc_callback_error"] = existing["reason"]
            else:
                request.session["oidc_callback_error"] = reason
            persist_session(request)
            return [None, None, None]
        request.session["oidc_callback_error"] = reason
        if code:
            store_code_replay(request, code, status="error", reason=reason)
        else:
            persist_session(request)
        return [None, None, None]

    def authentication_url(self, request):
        """Stable login-button URL. State is minted when the user clicks."""
        url = reverse("plugins:pretix_oidc:oidc_login")
        next_url = request.GET.get("next")
        if next_url:
            return url + "?next=" + quote(next_url, safe="")
        return url

    def authorize_redirect_url(self, request, purpose="login", link_user_id=None):
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
        try:
            auth_response = self.client.parse_response(
                AuthorizationResponse,
                info=request.META["QUERY_STRING"],
                sformat="urlencoded",
            )
        except Exception:
            logger.exception("OIDC authorization response could not be parsed")
            return self._callback_fail(request, "failed")

        code = auth_response.get("code")
        replay = get_code_replay(request, code)
        if replay and replay.get("status") in (*TERMINAL_REPLAY_STATUSES, "pending"):
            if replay.get("status") == "error" and replay.get("reason"):
                request.session["oidc_callback_error"] = replay["reason"]
                persist_session(request)
            return [None, None, None]

        response_state = auth_response.get("state", None)
        states = self._fresh_oidc_states(request)

        if not states or not response_state:
            request.session["oidc_state"] = states
            return self._callback_fail(request, "state_missing", code)

        if response_state not in states:
            request.session["oidc_state"] = states
            return self._callback_fail(request, "state_mismatch", code)

        state_data = states[response_state]
        if state_data.get("generated_on", 0) < time.time() - OIDC_STATE_TTL:
            states.pop(response_state, None)
            request.session["oidc_state"] = states
            return self._callback_fail(request, "state_expired", code)

        if not code:
            states.pop(response_state, None)
            request.session["oidc_state"] = states
            return self._callback_fail(request, "failed")

        if not claim_code_for_exchange(code):
            request.oidc_code_inflight = True
            return [None, None, None]

        states.pop(response_state, None)
        request.session["oidc_state"] = states
        request.session["oidc_callback_meta"] = {
            "purpose": state_data.get("purpose", "login"),
            "link_user_id": state_data.get("link_user_id"),
        }
        request.session["oidc_next_url"] = state_data.get("next")
        store_code_replay(
            request,
            code,
            status="pending",
            next=state_data.get("next"),
        )

        try:
            access_token_response = self.client.do_access_token_request(
                state=response_state,
                scope=self.scopes,
                request_args={
                    "code": code,
                    "redirect_uri": self.redirect_uri(request),
                },
                authn_method="client_secret_basic",
            )
        except Exception:
            logger.exception("OIDC access token request failed")
            return self._callback_fail(request, "token_request", code)

        token_response = claims_dict(access_token_response)
        if token_response.get("error"):
            logger.warning(
                "OIDC access token response error: %s", token_response["error"]
            )
            return self._callback_fail(request, "token_error", code)

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
            return self._callback_fail(request, "missing_id_token", code)

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
            return self._callback_fail(request, "missing_claims", code)

        user_data = {
            "uuid": uuid,
            "email": email,
            "fullname": fullname,
            "email_verified": email_verified,
            "auth_backend": self.identifier,
        }

        request.session.pop("oidc_callback_error", None)
        return [user_data, claims_dict(id_token), claims_dict(userinfo)]
