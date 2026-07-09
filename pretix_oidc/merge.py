import json
from django.db import transaction
from django.utils.translation import gettext_lazy as _
from django_otp.plugins.otp_static.models import StaticDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_scopes import scopes_disabled
from pretix.base.models import (
    LogEntry,
    NotificationSetting,
    U2FDevice,
    User,
    WebAuthnDevice,
)
from pretix.base.models.auth import HistoricPassword, UserKnownLoginSource
from pretix.base.models.mail import OutgoingMail
from pretix.base.models.orders import PrintLog

from .linking import (
    BACKEND_IDENTIFIER,
    apply_verified_email,
    link_native_user_to_oidc,
)


class UserMergeError(Exception):
    pass


def _anonymize_user(user):
    user.email = "{}.{}@disabled.pretix.eu".format(user.pk, user.auth_backend)
    user.fullname = ""
    user.is_active = False
    user.notifications_send = False
    user.auth_backend = "anonymized"
    user.auth_backend_identifier = None
    user.save()
    for le in user.all_logentries.filter(action_type="pretix.user.settings.changed"):
        data = le.parsed_data
        if "email" in data:
            data["email"] = "█"
        if "fullname" in data:
            data["fullname"] = "█"
        le.data = json.dumps(data)
        le.shredded = True
        le.save(update_fields=["data", "shredded"])


def _move_user_owned_rows(model, source, target):
    model.objects.filter(user=source).update(user=target)


def _reassign_login_sources(source, target):
    for src in UserKnownLoginSource.objects.filter(user=source):
        existing = UserKnownLoginSource.objects.filter(
            user=target,
            agent_type=src.agent_type,
            device_type=src.device_type,
            os_type=src.os_type,
            country=src.country,
        ).first()
        if existing:
            if src.last_seen > existing.last_seen:
                existing.last_seen = src.last_seen
                existing.save(update_fields=["last_seen"])
            src.delete()
        else:
            src.user = target
            src.save(update_fields=["user"])


def dedupe_login_sources(user):
    """Remove duplicate UserKnownLoginSource rows for a user."""
    _dedupe_login_sources(user)


def _dedupe_login_sources(user):
    unique_fields = ["agent_type", "device_type", "os_type", "country"]
    seen = {}
    for src in UserKnownLoginSource.objects.filter(user=user).order_by(
        "-last_seen", "-pk"
    ):
        key = tuple(getattr(src, field) for field in unique_fields)
        if key in seen:
            src.delete()
        else:
            seen[key] = src


def _reassign_notification_settings(source, target):
    for setting in NotificationSetting.objects.filter(user=source):
        if NotificationSetting.objects.filter(
            user=target,
            action_type=setting.action_type,
            event=setting.event,
            method=setting.method,
        ).exists():
            setting.delete()
        else:
            setting.user = target
            setting.save(update_fields=["user"])


def _reassign_otp_devices(source, target):
    for device in StaticDevice.objects.filter(user=source):
        if (
            device.name == "emergency"
            and StaticDevice.objects.filter(user=target, name="emergency").exists()
        ):
            device.delete()
        else:
            device.user = target
            device.save(update_fields=["user"])

    for model in (TOTPDevice, U2FDevice):
        _move_user_owned_rows(model, source, target)

    for device in WebAuthnDevice.objects.filter(user=source):
        if (
            device.credential_id
            and WebAuthnDevice.objects.filter(credential_id=device.credential_id)
            .exclude(pk=device.pk)
            .exists()
        ):
            device.delete()
        else:
            device.user = target
            device.save(update_fields=["user"])


def _merge_user_flags(source, target):
    update_fields = []
    if source.require_2fa and not target.require_2fa:
        target.require_2fa = True
        update_fields.append("require_2fa")
    if source.is_verified and not target.is_verified:
        target.is_verified = True
        update_fields.append("is_verified")
    if update_fields:
        target.save(update_fields=update_fields)


def _reassign_user_fks(source, target):
    _move_user_owned_rows(LogEntry, source, target)
    _move_user_owned_rows(OutgoingMail, source, target)
    _move_user_owned_rows(PrintLog, source, target)
    _move_user_owned_rows(HistoricPassword, source, target)
    _reassign_login_sources(source, target)
    dedupe_login_sources(target)
    _reassign_notification_settings(source, target)
    _reassign_otp_devices(source, target)
    _merge_user_flags(source, target)


def _merge_team_memberships(source, target):
    target.teams.add(*source.teams.all())


@transaction.atomic
def merge_oidc_user_into_native(native_user, oidc_user, *, acting_user=None):
    with scopes_disabled():
        native_user = User.objects.select_for_update().get(pk=native_user.pk)
        oidc_user = User.objects.select_for_update().get(pk=oidc_user.pk)

        if native_user.pk == oidc_user.pk:
            raise UserMergeError(_("Cannot merge a user with itself."))
        if native_user.auth_backend != "native":
            raise UserMergeError(
                _("The target account must use the native login backend.")
            )
        if oidc_user.auth_backend != BACKEND_IDENTIFIER:
            raise UserMergeError(_("The source account must use OpenID Connect."))
        if not oidc_user.auth_backend_identifier:
            raise UserMergeError(
                _("The OpenID Connect account has no external identifier.")
            )
        if not oidc_user.email:
            raise UserMergeError(_("The OpenID Connect account has no email address."))

        oidc_email = oidc_user.email
        oidc_identifier = oidc_user.auth_backend_identifier
        oidc_fullname = oidc_user.fullname
        email_verified = oidc_user.is_verified

        if (
            User.objects.filter(email__iexact=oidc_email)
            .exclude(pk__in=[native_user.pk, oidc_user.pk])
            .exists()
        ):
            raise UserMergeError(
                _("Another account already uses the OpenID Connect email address.")
            )

        _merge_team_memberships(oidc_user, native_user)
        _reassign_user_fks(oidc_user, native_user)
        _anonymize_user(oidc_user)

        native_user.email = oidc_email
        native_user.save(update_fields=["email"])

        native_user = link_native_user_to_oidc(
            native_user,
            oidc_identifier,
            oidc_email,
            oidc_fullname,
            email_verified=email_verified,
        )
        apply_verified_email(
            native_user, {"email_verified": email_verified if email_verified else None}
        )

        return native_user


@transaction.atomic
def convert_oidc_user_to_native(
    user,
    *,
    password,
    needs_password_change=False,
    acting_user=None,
):
    with scopes_disabled():
        user = User.objects.select_for_update().get(pk=user.pk)

        if user.auth_backend != BACKEND_IDENTIFIER:
            raise UserMergeError(_("The account must use OpenID Connect."))
        if not user.auth_backend_identifier:
            raise UserMergeError(
                _("The OpenID Connect account has no external identifier.")
            )

        user.set_password(password)
        user.needs_password_change = needs_password_change
        user.auth_backend = "native"
        user.save(
            update_fields=[
                "password",
                "needs_password_change",
                "auth_backend",
            ]
        )

        return user
