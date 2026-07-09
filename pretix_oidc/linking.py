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
    """Mark the session dirty; let Django save it with the response.

    Do not call session.save() here. An eager save can race with other
    concurrent requests and overwrite unrelated session keys such as
    pretix_auth_2fa_user during the 2FA login step.
    """
    if hasattr(request.session, "modified"):
        request.session.modified = True


def clear_stale_auth_session(request, user):
    """Drop django auth session keys that refer to a different user.

    During 2FA, pretix stores the user pk in pretix_auth_2fa_user but does
    not log the user in yet. If _auth_user_id still points at another account
    (common after merging OIDC into native), django.contrib.auth.login()
    calls session.flush() when the passkey step succeeds. That wipes
    pretix_auth_2fa_user and pretix's Login2FAView then crashes with KeyError.
    """
    from django.contrib.auth import (
        BACKEND_SESSION_KEY,
        HASH_SESSION_KEY,
        SESSION_KEY,
    )

    stored_pk = request.session.get(SESSION_KEY)
    if stored_pk is None:
        return
    try:
        matches = int(stored_pk) == user.pk
    except (TypeError, ValueError):
        matches = False
    if not matches:
        request.session.pop(SESSION_KEY, None)
        request.session.pop(BACKEND_SESSION_KEY, None)
        request.session.pop(HASH_SESSION_KEY, None)


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
