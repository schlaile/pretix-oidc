import pytest
from datetime import timedelta
from django.test import RequestFactory, override_settings
from django.utils.timezone import now
from django_otp.plugins.otp_static.models import StaticDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_scopes import scopes_disabled
from pretix.base.models import (
    NotificationSetting,
    Organizer,
    Team,
    U2FDevice,
    User,
    WebAuthnDevice,
)
from pretix.base.models.auth import HistoricPassword, UserKnownLoginSource
from pretix.helpers.security import handle_login_source
from unittest.mock import patch

from pretix_oidc.merge import (
    UserMergeError,
    convert_oidc_user_to_native,
    dedupe_login_sources,
    merge_oidc_user_into_native,
)

CHROME_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
)


@pytest.fixture
def staff_user(db):
    with scopes_disabled():
        user = User.objects.create_user("staff@example.com", "password")
        user.is_staff = True
        user.save()
        return user


@pytest.fixture
def organizer(db):
    with scopes_disabled():
        return Organizer.objects.create(name="Org", slug="org")


@pytest.fixture
def native_user(db):
    with scopes_disabled():
        return User.objects.create_user("native@example.com", "password")


@pytest.fixture
def oidc_user(db):
    with scopes_disabled():
        user = User.objects.create_user("oidc@example.com", "password")
        user.auth_backend = "pretix_oidc"
        user.auth_backend_identifier = "sub-merge-default"
        user.save()
        return user


def _login_source(
    user,
    *,
    agent="Chrome",
    device="Mac",
    os="Mac OS X",
    country="DE",
    last_seen=None,
):
    return UserKnownLoginSource.objects.create(
        user=user,
        agent_type=agent,
        device_type=device,
        os_type=os,
        country=country,
        last_seen=last_seen or now(),
    )


def _merge(native, oidc, staff_user):
    return merge_oidc_user_into_native(native, oidc, acting_user=staff_user)


class _SessionStore(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.modified = False

    def save(self):
        raise AssertionError("session.save() must not be called during login URL build")

    # Used by django.contrib.auth.login(): a flush would drop the 2FA keys,
    # cycling the key keeps them (as with a real session backend).
    def flush(self):
        self.clear()

    def cycle_key(self):
        pass


@pytest.mark.django_db
def test_merge_oidc_user_into_native_success(
    staff_user, organizer, native_user, oidc_user
):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-merge-1"
        oidc_user.is_verified = True
        oidc_user.save()
        team = Team.objects.create(organizer=organizer, name="Team", all_events=True)
        team.members.add(oidc_user)

    merged = _merge(native_user, oidc_user, staff_user)

    merged.refresh_from_db()
    oidc_user.refresh_from_db()

    assert merged.pk == native_user.pk
    assert merged.email == "oidc@example.com"
    assert merged.auth_backend == "pretix_oidc"
    assert merged.auth_backend_identifier == "sub-merge-1"
    assert merged.is_verified is True
    assert not merged.has_usable_password()
    assert team in merged.teams.all()
    assert oidc_user.auth_backend == "anonymized"
    assert oidc_user.is_active is False


@pytest.mark.django_db
def test_merge_rejects_non_native_target(staff_user):
    with scopes_disabled():
        first = User.objects.create_user("first@example.com", "password")
        first.auth_backend = "pretix_oidc"
        first.auth_backend_identifier = "sub-1"
        first.save()
        second = User.objects.create_user("second@example.com", "password")
        second.auth_backend = "pretix_oidc"
        second.auth_backend_identifier = "sub-2"
        second.save()

    with pytest.raises(UserMergeError):
        _merge(first, second, staff_user)


@pytest.mark.django_db
def test_merge_rejects_non_oidc_source(staff_user, native_user):
    with scopes_disabled():
        other = User.objects.create_user("other@example.com", "password")

    with pytest.raises(UserMergeError):
        _merge(native_user, other, staff_user)


@pytest.mark.django_db
def test_merge_rejects_same_user(staff_user, native_user):
    with pytest.raises(UserMergeError):
        _merge(native_user, native_user, staff_user)


@pytest.mark.django_db
def test_merge_rejects_oidc_without_identifier(staff_user, native_user, oidc_user):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = None
        oidc_user.save()

    with pytest.raises(UserMergeError):
        _merge(native_user, oidc_user, staff_user)


@pytest.mark.django_db
def test_merge_rejects_oidc_without_email(staff_user, native_user, oidc_user):
    with scopes_disabled():
        oidc_user.email = ""
        oidc_user.save()

    with pytest.raises(UserMergeError):
        _merge(native_user, oidc_user, staff_user)


@pytest.mark.django_db
def test_merge_rejects_conflicting_email(staff_user, native_user, oidc_user):
    with scopes_disabled():
        # User.email is unique and lowercased on save, so a conflicting
        # account can only be a legacy row differing in case.
        other = User.objects.create_user("legacy@example.com", "password")
        User.objects.filter(pk=other.pk).update(email="Other@Example.com")
        oidc_user.email = "other@example.com"
        oidc_user.save()

    with pytest.raises(UserMergeError):
        _merge(native_user, oidc_user, staff_user)


@pytest.mark.django_db
def test_merge_deduplicates_conflicting_login_sources(
    staff_user, native_user, oidc_user
):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-login-source"
        oidc_user.save()
        newer = now()
        _login_source(
            native_user,
            last_seen=now() - timedelta(days=1),
        )
        _login_source(oidc_user, last_seen=newer)

    _merge(native_user, oidc_user, staff_user)

    native_user.refresh_from_db()
    sources = UserKnownLoginSource.objects.filter(user=native_user)
    assert sources.count() == 1
    assert sources.get().last_seen == newer


@pytest.mark.django_db
def test_merge_keeps_distinct_login_sources(staff_user, native_user, oidc_user):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-login-source-2"
        oidc_user.save()
        _login_source(native_user, agent="Chrome")
        _login_source(oidc_user, agent="Firefox", os="Mac OS X")

    _merge(native_user, oidc_user, staff_user)

    sources = UserKnownLoginSource.objects.filter(user=native_user)
    assert sources.count() == 2
    assert set(sources.values_list("agent_type", flat=True)) == {"Chrome", "Firefox"}


@pytest.mark.django_db
def test_handle_login_source_after_merge(staff_user, native_user, oidc_user):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-2fa-login"
        oidc_user.save()
        # Without GeoIP, pretix stores country=None for the new login.
        _login_source(native_user, country=None)
        _login_source(oidc_user, country=None)

    _merge(native_user, oidc_user, staff_user)

    factory = RequestFactory()
    request = factory.post(
        "/control/login/2fa/",
        HTTP_USER_AGENT=CHROME_UA,
    )
    request.session = _SessionStore(
        pretix_auth_2fa_user=native_user.pk,
        pretix_auth_2fa_time=str(int(now().timestamp())),
    )

    with patch("pretix.helpers.security.settings.HAS_GEOIP", False):
        handle_login_source(native_user, request)

    assert UserKnownLoginSource.objects.filter(user=native_user).count() == 1
    assert request.session["pretix_auth_2fa_user"] == native_user.pk


@pytest.mark.django_db
@override_settings(
    PRETIX_AUTH_BACKENDS=[
        "pretix.base.auth.NativeAuthBackend",
        "pretix_oidc.auth.OIDCAuthBackend",
    ]
)
def test_oidc_login_clears_stale_session_before_2fa(staff_user, native_user, oidc_user):
    from django.contrib.auth import SESSION_KEY, login as auth_login

    from pretix_oidc.views import _finish_oidc_login

    oidc_pk = oidc_user.pk
    with scopes_disabled():
        native_user.require_2fa = True
        native_user.save()
        oidc_user.auth_backend_identifier = "sub-stale-session"
        oidc_user.save()

    _merge(native_user, oidc_user, staff_user)
    native_user.refresh_from_db()

    factory = RequestFactory()
    request = factory.get("/oidc/callback/")
    request.session = _SessionStore(
        **{
            SESSION_KEY: str(oidc_pk),
            "pretix_auth_2fa_user": native_user.pk,
            "pretix_auth_2fa_time": str(int(now().timestamp())),
        }
    )

    with patch("pretix_oidc.views.add_user_to_teams"), patch(
        "pretix_oidc.views.add_user_to_staff"
    ):
        response = _finish_oidc_login(request, native_user, {}, {})

    assert response.status_code == 302
    assert "2fa" in response.url
    assert request.session["pretix_auth_2fa_user"] == native_user.pk
    assert SESSION_KEY not in request.session

    auth_login(request, native_user)
    assert request.session["pretix_auth_2fa_user"] == native_user.pk


def _login_source_is_unique():
    return any(
        set(u) >= {"user", "agent_type", "device_type", "os_type", "country"}
        for u in UserKnownLoginSource._meta.unique_together
    )


@pytest.mark.django_db
@pytest.mark.skipif(
    _login_source_is_unique(),
    reason="pretix enforces unique login sources (migration 0278), "
    "duplicates cannot exist",
)
def test_dedupe_login_sources_repairs_existing_duplicates(native_user):
    with scopes_disabled():
        _login_source(native_user)
        UserKnownLoginSource.objects.create(
            user=native_user,
            agent_type="Chrome",
            device_type="Mac",
            os_type="Mac OS X",
            country="DE",
            last_seen=now() - timedelta(days=2),
        )

    dedupe_login_sources(native_user)

    assert UserKnownLoginSource.objects.filter(user=native_user).count() == 1


@pytest.mark.django_db
def test_merge_deduplicates_conflicting_notification_settings(
    staff_user, native_user, oidc_user
):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-notify"
        oidc_user.save()
        NotificationSetting.objects.create(
            user=native_user,
            action_type="pretix.event.order.placed",
            event=None,
            method="mail",
            enabled=True,
        )
        NotificationSetting.objects.create(
            user=oidc_user,
            action_type="pretix.event.order.placed",
            event=None,
            method="mail",
            enabled=False,
        )

    _merge(native_user, oidc_user, staff_user)

    settings = NotificationSetting.objects.filter(
        user=native_user,
        action_type="pretix.event.order.placed",
        event=None,
        method="mail",
    )
    assert settings.count() == 1
    assert settings.get().enabled is True


@pytest.mark.django_db
def test_merge_moves_non_conflicting_notification_settings(
    staff_user, native_user, oidc_user
):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-notify-2"
        oidc_user.save()
        NotificationSetting.objects.create(
            user=oidc_user,
            action_type="pretix.event.order.changed",
            event=None,
            method="mail",
            enabled=True,
        )

    _merge(native_user, oidc_user, staff_user)

    assert NotificationSetting.objects.filter(
        user=native_user,
        action_type="pretix.event.order.changed",
    ).exists()


@pytest.mark.django_db
def test_merge_keeps_single_emergency_static_device(staff_user, native_user, oidc_user):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-2fa"
        oidc_user.save()
        StaticDevice.objects.create(user=native_user, name="emergency")
        oidc_emergency = StaticDevice.objects.create(user=oidc_user, name="emergency")

    _merge(native_user, oidc_user, staff_user)

    emergency = StaticDevice.objects.filter(user=native_user, name="emergency")
    assert emergency.count() == 1
    assert not StaticDevice.objects.filter(pk=oidc_emergency.pk).exists()


@pytest.mark.django_db
def test_merge_moves_totp_device(staff_user, native_user, oidc_user):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-totp"
        oidc_user.save()
        device = TOTPDevice.objects.create(
            user=oidc_user,
            name="Authenticator",
            confirmed=True,
        )

    _merge(native_user, oidc_user, staff_user)

    device.refresh_from_db()
    assert device.user_id == native_user.pk


@pytest.mark.django_db
def test_merge_moves_u2f_device(staff_user, native_user, oidc_user):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-u2f"
        oidc_user.save()
        device = U2FDevice.objects.create(
            user=oidc_user,
            name="U2F key",
            confirmed=True,
            json_data="{}",
        )

    _merge(native_user, oidc_user, staff_user)

    device.refresh_from_db()
    assert device.user_id == native_user.pk


@pytest.mark.django_db
def test_merge_moves_webauthn_device_from_oidc_account(
    staff_user, native_user, oidc_user
):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-webauthn"
        oidc_user.save()
        device = WebAuthnDevice.objects.create(
            user=oidc_user,
            name="YubiKey",
            confirmed=True,
            credential_id="cred-oidc-only",
        )

    _merge(native_user, oidc_user, staff_user)

    device.refresh_from_db()
    assert device.user_id == native_user.pk


@pytest.mark.django_db
def test_merge_keeps_both_webauthn_devices_when_credentials_differ(
    staff_user, native_user, oidc_user
):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-webauthn-2"
        oidc_user.save()
        WebAuthnDevice.objects.create(
            user=native_user,
            name="Native key",
            confirmed=True,
            credential_id="cred-native",
        )
        oidc_device = WebAuthnDevice.objects.create(
            user=oidc_user,
            name="OIDC key",
            confirmed=True,
            credential_id="cred-oidc",
        )

    _merge(native_user, oidc_user, staff_user)

    oidc_device.refresh_from_db()
    assert oidc_device.user_id == native_user.pk
    assert WebAuthnDevice.objects.filter(user=native_user).count() == 2


@pytest.mark.django_db
def test_merge_drops_duplicate_webauthn_credential_id(
    staff_user, native_user, oidc_user
):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-webauthn-dup"
        oidc_user.save()
        WebAuthnDevice.objects.create(
            user=native_user,
            name="Shared key",
            confirmed=True,
            credential_id="cred-shared",
        )
        duplicate = WebAuthnDevice.objects.create(
            user=oidc_user,
            name="Shared key copy",
            confirmed=True,
            credential_id="cred-shared",
        )

    _merge(native_user, oidc_user, staff_user)

    assert (
        WebAuthnDevice.objects.filter(
            user=native_user, credential_id="cred-shared"
        ).count()
        == 1
    )
    assert not WebAuthnDevice.objects.filter(pk=duplicate.pk).exists()


@pytest.mark.django_db
def test_merge_moves_historic_passwords(staff_user, native_user, oidc_user):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-historic"
        oidc_user.save()
        historic = HistoricPassword.objects.create(
            user=oidc_user,
            password="hashed-old-password",
        )

    _merge(native_user, oidc_user, staff_user)

    historic.refresh_from_db()
    assert historic.user_id == native_user.pk


@pytest.mark.django_db
def test_merge_moves_log_entries(staff_user, native_user, oidc_user):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-log"
        oidc_user.save()
        entry = oidc_user.log_action(
            "pretix.user.settings.changed",
            user=oidc_user,
            data={"email": "oidc@example.com"},
        )

    _merge(native_user, oidc_user, staff_user)

    entry.refresh_from_db()
    assert entry.user_id == native_user.pk


@pytest.mark.django_db
def test_merge_combines_team_memberships(staff_user, organizer, native_user, oidc_user):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-teams"
        oidc_user.save()
        team_native = Team.objects.create(
            organizer=organizer, name="Native team", all_events=True
        )
        team_oidc = Team.objects.create(
            organizer=organizer, name="OIDC team", all_events=True
        )
        team_native.members.add(native_user)
        team_oidc.members.add(oidc_user)

    _merge(native_user, oidc_user, staff_user)

    team_ids = set(native_user.teams.values_list("pk", flat=True))
    assert team_ids == {team_native.pk, team_oidc.pk}


@pytest.mark.django_db
def test_merge_propagates_require_2fa_flag(staff_user, native_user, oidc_user):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-2fa-flag"
        oidc_user.require_2fa = True
        oidc_user.save()

    _merge(native_user, oidc_user, staff_user)

    native_user.refresh_from_db()
    assert native_user.require_2fa is True


@pytest.mark.django_db
def test_merge_propagates_is_verified_flag(staff_user, native_user, oidc_user):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = "sub-verified"
        oidc_user.is_verified = True
        oidc_user.save()

    _merge(native_user, oidc_user, staff_user)

    native_user.refresh_from_db()
    assert native_user.is_verified is True


@pytest.mark.django_db
def test_convert_oidc_user_to_native_success(staff_user, organizer):
    with scopes_disabled():
        oidc = User.objects.create_user("oidc@example.com", "password")
        oidc.auth_backend = "pretix_oidc"
        oidc.auth_backend_identifier = "sub-native-convert"
        oidc.is_verified = True
        oidc.save()
        team = Team.objects.create(organizer=organizer, name="Team B", all_events=True)
        team.members.add(oidc)

    converted = convert_oidc_user_to_native(
        oidc,
        password="new-secure-password",
        needs_password_change=True,
        acting_user=staff_user,
    )

    converted.refresh_from_db()

    assert converted.pk == oidc.pk
    assert converted.email == "oidc@example.com"
    assert converted.auth_backend == "native"
    assert converted.auth_backend_identifier == "sub-native-convert"
    assert converted.is_verified is True
    assert converted.needs_password_change is True
    assert converted.check_password("new-secure-password")
    assert team in converted.teams.all()


@pytest.mark.django_db
def test_convert_rejects_non_oidc_user(staff_user, native_user):
    with pytest.raises(UserMergeError):
        convert_oidc_user_to_native(native_user, password="new-password")


@pytest.mark.django_db
def test_convert_rejects_oidc_without_identifier(staff_user, oidc_user):
    with scopes_disabled():
        oidc_user.auth_backend_identifier = None
        oidc_user.save()

    with pytest.raises(UserMergeError):
        convert_oidc_user_to_native(oidc_user, password="new-password")
