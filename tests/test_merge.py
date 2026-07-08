import pytest
from django.test import RequestFactory
from django_scopes import scopes_disabled
from pretix.base.models import Organizer, Team, User
from unittest.mock import patch

from pretix_oidc.merge import UserMergeError, merge_oidc_user_into_native


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


@pytest.mark.django_db
def test_merge_oidc_user_into_native_success(staff_user, organizer):
    with scopes_disabled():
        native = User.objects.create_user("native@example.com", "password")
        oidc = User.objects.create_user("oidc@example.com", "password")
        oidc.auth_backend = "pretix_oidc"
        oidc.auth_backend_identifier = "sub-merge-1"
        oidc.is_verified = True
        oidc.save()

        team = Team.objects.create(organizer=organizer, name="Team", all_events=True)
        team.members.add(oidc)

    merged = merge_oidc_user_into_native(native, oidc, acting_user=staff_user)

    merged.refresh_from_db()
    oidc.refresh_from_db()

    assert merged.pk == native.pk
    assert merged.email == "oidc@example.com"
    assert merged.auth_backend == "pretix_oidc"
    assert merged.auth_backend_identifier == "sub-merge-1"
    assert merged.is_verified is True
    assert not merged.has_usable_password()
    assert team in merged.teams.all()
    assert oidc.auth_backend == "anonymized"
    assert oidc.is_active is False


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
        merge_oidc_user_into_native(first, second, acting_user=staff_user)


@pytest.mark.django_db
def test_merge_rejects_non_oidc_source(staff_user):
    with scopes_disabled():
        native = User.objects.create_user("native@example.com", "password")
        other = User.objects.create_user("other@example.com", "password")

    with pytest.raises(UserMergeError):
        merge_oidc_user_into_native(native, other, acting_user=staff_user)


@pytest.mark.django_db
def test_merge_rejects_same_user(staff_user):
    with scopes_disabled():
        native = User.objects.create_user("native@example.com", "password")

    with pytest.raises(UserMergeError):
        merge_oidc_user_into_native(native, native, acting_user=staff_user)


@pytest.mark.django_db
def test_convert_oidc_user_to_native_success(staff_user, organizer):
    from pretix_oidc.merge import convert_oidc_user_to_native

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
