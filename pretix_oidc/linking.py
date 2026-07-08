import json
import time
from django.db import transaction
from django.utils.translation import gettext_lazy as _
from django_scopes import scopes_disabled
from pretix.base.models import User
from pretix.settings import config

PENDING_LINK_SESSION_KEY = "pretix_oidc_pending_link"
PENDING_LINK_TTL = 15 * 60
BACKEND_IDENTIFIER = "pretix_oidc"
DEFAULT_ALLOW_ACCOUNT_LINKING = True
DEFAULT_REQUIRE_EMAIL_VERIFIED = True


class AccountLinkingError(Exception):
    pass


def require_email_verified():
    try:
        return config.getboolean(
            "oidc",
            "require_email_verified",
            fallback=DEFAULT_REQUIRE_EMAIL_VERIFIED,
        )
    except (ValueError, TypeError):
        return DEFAULT_REQUIRE_EMAIL_VERIFIED


def parse_email_verified(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "1", "yes"):
            return True
        if lowered in ("false", "0", "no"):
            return False
    return None


def ensure_email_verified(user_data):
    verified = parse_email_verified(user_data.get("email_verified"))
    if verified is False:
        return _(
            "The email address from OpenID Connect is not verified. Please confirm "
            "your email address with your identity provider first."
        )
    if verified is True:
        return None
    if require_email_verified():
        return _(
            "The email address from OpenID Connect is not verified. Please confirm "
            "your email address with your identity provider first."
        )
    return None


def apply_verified_email(user, user_data):
    if parse_email_verified(user_data.get("email_verified")) is True:
        if not user.is_verified:
            user.is_verified = True
            user.save(update_fields=["is_verified"])


def allow_account_linking():
    try:
        return config.getboolean(
            "oidc",
            "allow_account_linking",
            fallback=DEFAULT_ALLOW_ACCOUNT_LINKING,
        )
    except (ValueError, TypeError):
        return DEFAULT_ALLOW_ACCOUNT_LINKING


def persist_session(request):
    if hasattr(request.session, "modified"):
        request.session.modified = True
    if hasattr(request.session, "save"):
        request.session.save()


def session_safe_claims(data):
    if not data:
        return {}
    return json.loads(json.dumps(data, default=str))


def find_native_user_by_email(email):
    with scopes_disabled():
        return User.objects.filter(email__iexact=email, auth_backend="native").first()


def find_converted_native_user(uuid):
    if not uuid:
        return None
    with scopes_disabled():
        return User.objects.filter(
            auth_backend="native",
            auth_backend_identifier=uuid,
            is_active=True,
        ).first()


def store_pending_link(request, user_data, id_token, userinfo):
    request.session[PENDING_LINK_SESSION_KEY] = {
        "uuid": user_data["uuid"],
        "email": user_data["email"],
        "fullname": user_data.get("fullname"),
        "email_verified": user_data.get("email_verified"),
        "id_token": session_safe_claims(id_token),
        "userinfo": session_safe_claims(userinfo),
        "generated_on": int(time.time()),
    }
    persist_session(request)


def get_pending_link(request):
    pending = request.session.get(PENDING_LINK_SESSION_KEY)
    if not pending:
        return None
    if pending["generated_on"] < time.time() - PENDING_LINK_TTL:
        clear_pending_link(request)
        return None
    return pending


def clear_pending_link(request):
    request.session.pop(PENDING_LINK_SESSION_KEY, None)
    persist_session(request)


@transaction.atomic
def link_native_user_to_oidc(
    user, identifier, email, fullname=None, email_verified=None
):
    if not allow_account_linking():
        raise AccountLinkingError(_("Account linking is disabled."))
    if user.auth_backend != "native":
        raise AccountLinkingError(_("Only native accounts can be linked."))
    if user.email.lower() != email.lower():
        raise AccountLinkingError(_("Email addresses do not match."))
    if (
        User.objects.filter(
            auth_backend=BACKEND_IDENTIFIER, auth_backend_identifier=identifier
        )
        .exclude(pk=user.pk)
        .exists()
    ):
        raise AccountLinkingError(
            _("This OpenID identity is already linked to another account.")
        )

    user.auth_backend = BACKEND_IDENTIFIER
    user.auth_backend_identifier = identifier
    if fullname:
        user.fullname = fullname
    user.set_unusable_password()
    update_fields = [
        "auth_backend",
        "auth_backend_identifier",
        "fullname",
        "password",
    ]
    if parse_email_verified(email_verified) is True:
        user.is_verified = True
        update_fields.append("is_verified")
    user.save(update_fields=update_fields)
    return user
