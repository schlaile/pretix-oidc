import json
from django.db import transaction
from django.utils.translation import gettext_lazy as _
from django_scopes import scopes_disabled
from pretix.base.models import LogEntry, NotificationSetting, User
from pretix.base.models.auth import UserKnownLoginSource
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


def _reassign_user_fks(source, target):
    LogEntry.objects.filter(user=source).update(user=target)
    OutgoingMail.objects.filter(user=source).update(user=target)
    PrintLog.objects.filter(user=source).update(user=target)
    UserKnownLoginSource.objects.filter(user=source).update(user=target)

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
