import pytest
import time
from django.test import RequestFactory
from django_scopes import scopes_disabled
from pretix.base.models import User
from pretix.base.models.auth import EmailAddressTakenError
from unittest.mock import MagicMock, patch

from pretix_oidc.linking import (
    PENDING_LINK_SESSION_KEY,
    AccountLinkingError,
    clear_pending_link,
    get_pending_link,
    link_native_user_to_oidc,
    store_pending_link,
)


@pytest.mark.django_db
def test_link_native_user_to_oidc_success():
    with scopes_disabled():
        user = User.objects.create_user("native@example.com", "password")
        assert user.auth_backend == "native"

        linked = link_native_user_to_oidc(
            user, "sub-oidc-1", "native@example.com", "Native User"
        )

        linked.refresh_from_db()
        assert linked.auth_backend == "pretix_oidc"
        assert linked.auth_backend_identifier == "sub-oidc-1"
        assert linked.fullname == "Native User"
        assert not linked.has_usable_password()


@pytest.mark.django_db
def test_link_native_user_sets_is_verified():
    with scopes_disabled():
        user = User.objects.create_user("native@example.com", "password")

        linked = link_native_user_to_oidc(
            user,
            "sub-oidc-1",
            "native@example.com",
            email_verified=True,
        )

        linked.refresh_from_db()
        assert linked.is_verified is True


@pytest.mark.django_db
def test_link_native_user_rejects_email_mismatch():
    with scopes_disabled():
        user = User.objects.create_user("native@example.com", "password")

    with pytest.raises(AccountLinkingError):
        link_native_user_to_oidc(user, "sub-oidc-1", "other@example.com")


@pytest.mark.django_db
def test_link_native_user_rejects_non_native():
    with scopes_disabled():
        user = User.objects.create_user("oidc@example.com", "password")
        user.auth_backend = "pretix_oidc"
        user.auth_backend_identifier = "sub-existing"
        user.save()

    with pytest.raises(AccountLinkingError):
        link_native_user_to_oidc(user, "sub-new", "oidc@example.com")


@pytest.mark.django_db
def test_link_native_user_rejects_identifier_taken():
    with scopes_disabled():
        User.objects.create_user("oidc@example.com", "password")
        oidc_user = User.objects.get(email="oidc@example.com")
        oidc_user.auth_backend = "pretix_oidc"
        oidc_user.auth_backend_identifier = "sub-taken"
        oidc_user.save()

        native = User.objects.create_user("native@example.com", "password")

    with pytest.raises(AccountLinkingError):
        link_native_user_to_oidc(native, "sub-taken", "native@example.com")


def test_pending_link_session_roundtrip():
    factory = RequestFactory()
    request = factory.get("/")
    request.session = {}

    store_pending_link(
        request,
        {"uuid": "sub-1", "email": "user@example.com", "fullname": "User"},
        {"sub": "sub-1"},
        {"email": "user@example.com"},
    )

    pending = get_pending_link(request)
    assert pending["uuid"] == "sub-1"
    assert pending["email"] == "user@example.com"

    clear_pending_link(request)
    assert get_pending_link(request) is None


def test_pending_link_expires():
    factory = RequestFactory()
    request = factory.get("/")
    request.session = {}

    store_pending_link(
        request,
        {"uuid": "sub-1", "email": "user@example.com", "fullname": "User"},
        {},
        {},
    )
    request.session[PENDING_LINK_SESSION_KEY]["generated_on"] = int(time.time()) - 3600

    assert get_pending_link(request) is None


@pytest.mark.django_db
@patch("pretix_oidc.views.allow_account_linking", return_value=False)
@patch("pretix_oidc.views.OIDCAuthBackend")
def test_oidc_callback_hard_fail_when_linking_disabled(backend_cls, _allow):
    from django.urls import reverse

    from pretix_oidc.views import oidc_callback

    with scopes_disabled():
        User.objects.create_user("native@example.com", "password")

    backend = backend_cls.return_value
    backend.identifier = "pretix_oidc"
    backend.process_callback.return_value = [
        {
            "uuid": "sub-other",
            "email": "native@example.com",
            "fullname": "Native",
            "email_verified": True,
            "auth_backend": "pretix_oidc",
        },
        {},
        {},
    ]

    factory = RequestFactory()
    request = factory.get("/oidc/callback/")
    request.session = {}

    with patch("pretix_oidc.views.messages") as msg_mock:
        response = oidc_callback(request)

    assert response.status_code == 302
    assert response.url == reverse("control:auth.login") + "?backend=native"
    msg_mock.error.assert_called_once()
    assert "username and password" in msg_mock.error.call_args[0][1]
    assert "native@example.com" in msg_mock.error.call_args[0][1]


@pytest.mark.django_db
@patch("pretix_oidc.views.allow_account_linking", return_value=True)
@patch("pretix_oidc.views.OIDCAuthBackend")
def test_oidc_callback_redirects_converted_user_to_native_login(backend_cls, _allow):
    from django.urls import reverse

    from pretix_oidc.merge import convert_oidc_user_to_native
    from pretix_oidc.views import oidc_callback

    with scopes_disabled():
        oidc = User.objects.create_user("oidc@example.com", "password")
        oidc.auth_backend = "pretix_oidc"
        oidc.auth_backend_identifier = "sub-converted"
        oidc.save()
        convert_oidc_user_to_native(oidc, password="new-secure-password")

    backend = backend_cls.return_value
    backend.identifier = "pretix_oidc"
    backend.process_callback.return_value = [
        {
            "uuid": "sub-converted",
            "email": "oidc@example.com",
            "fullname": "OIDC User",
            "email_verified": True,
            "auth_backend": "pretix_oidc",
        },
        {},
        {},
    ]

    factory = RequestFactory()
    request = factory.get("/oidc/callback/")
    request.session = {}

    with patch("pretix_oidc.views.messages") as msg_mock:
        response = oidc_callback(request)

    assert response.status_code == 302
    assert response.url == reverse("control:auth.login") + "?backend=native"
    msg_mock.error.assert_called_once()
    assert "password login" in msg_mock.error.call_args[0][1].lower()
    assert "disabled" in msg_mock.error.call_args[0][1].lower()


@pytest.mark.django_db
@patch("pretix_oidc.views.allow_account_linking", return_value=True)
@patch("pretix_oidc.views.OIDCAuthBackend")
def test_oidc_callback_conflict_redirects_to_choice(backend_cls, _allow):
    from django.urls import reverse

    from pretix_oidc.linking import get_pending_link
    from pretix_oidc.views import oidc_callback

    with scopes_disabled():
        User.objects.create_user("native@example.com", "password")

    backend = backend_cls.return_value
    backend.identifier = "pretix_oidc"
    backend.process_callback.return_value = [
        {
            "uuid": "sub-new",
            "email": "native@example.com",
            "fullname": "Native",
            "email_verified": True,
            "auth_backend": "pretix_oidc",
        },
        {"groups": []},
        {},
    ]

    factory = RequestFactory()
    request = factory.get("/oidc/callback/")
    request.session = {}

    response = oidc_callback(request)

    assert response.status_code == 302
    assert response.url == reverse("plugins:pretix_oidc:oidc_link_choice")
    pending = get_pending_link(request)
    assert pending["email"] == "native@example.com"
    assert pending["uuid"] == "sub-new"


@pytest.mark.django_db
@patch("pretix_oidc.views.allow_account_linking", return_value=True)
@patch("pretix_oidc.views.OIDCAuthBackend")
def test_oidc_callback_rejects_unverified_email(backend_cls, _allow):
    from django.urls import reverse

    from pretix_oidc.views import oidc_callback

    backend = backend_cls.return_value
    backend.identifier = "pretix_oidc"
    backend.process_callback.return_value = [
        {
            "uuid": "sub-new",
            "email": "user@example.com",
            "fullname": "User",
            "email_verified": False,
            "auth_backend": "pretix_oidc",
        },
        {},
        {},
    ]

    factory = RequestFactory()
    request = factory.get("/oidc/callback/")
    request.session = {}

    with patch("pretix_oidc.views.messages") as msg_mock:
        response = oidc_callback(request)

    assert response.status_code == 302
    assert response.url == reverse("control:auth.login") + "?backend=native"
    msg_mock.error.assert_called_once()
    assert "not verified" in msg_mock.error.call_args[0][1].lower()


@pytest.mark.django_db
@patch("pretix_oidc.views.OIDCAuthBackend")
def test_oidc_callback_failure_shows_login_message(backend_cls):
    from django.urls import reverse

    from pretix_oidc.views import oidc_callback

    backend_cls.return_value.process_callback.return_value = [None, None, None]

    factory = RequestFactory()
    request = factory.get("/oidc/callback/")
    request.session = {}

    with patch("pretix_oidc.views.messages") as msg_mock:
        response = oidc_callback(request)

    assert response.status_code == 302
    assert response.url == reverse("control:auth.login") + "?backend=native"
    msg_mock.error.assert_called_once()
    assert "OpenID Connect sign-in failed" in msg_mock.error.call_args[0][1]


def test_link_auth_redirect_builds_native_login_url():
    from django.contrib.messages.storage.fallback import FallbackStorage
    from django.urls import reverse
    from urllib.parse import unquote

    from pretix_oidc.views import OIDCLinkAuthRedirectView

    factory = RequestFactory()
    request = factory.get("/control/oidc/link/auth/")
    request.session = {}
    setattr(request, "_messages", FallbackStorage(request))

    store_pending_link(
        request,
        {"uuid": "sub-1", "email": "user@example.com", "fullname": "User"},
        {},
        {},
    )

    with patch("pretix_oidc.views.allow_account_linking", return_value=True):
        response = OIDCLinkAuthRedirectView.as_view()(request)

    complete_url = reverse("plugins:pretix_oidc:oidc_link_complete")
    assert response.status_code == 302
    assert "backend=native" in response.url
    assert unquote(response.url).endswith(complete_url)

    stored = list(request._messages)
    assert len(stored) == 1
    assert "log in with your pretix account" in str(stored[0]).lower()


@pytest.mark.django_db
def test_link_complete_migrates_user():
    from django.contrib.messages.storage.fallback import FallbackStorage
    from django.urls import reverse

    from pretix_oidc.linking import get_pending_link
    from pretix_oidc.views import OIDCLinkCompleteView

    with scopes_disabled():
        user = User.objects.create_user("native@example.com", "password")

    factory = RequestFactory()
    request = factory.get(reverse("plugins:pretix_oidc:oidc_link_complete"))
    request.user = user
    request.session = {}
    setattr(request, "_messages", FallbackStorage(request))

    store_pending_link(
        request,
        {
            "uuid": "sub-linked",
            "email": "native@example.com",
            "fullname": "Linked",
            "email_verified": True,
        },
        {"groups": []},
        {},
    )

    with patch("pretix_oidc.views.allow_account_linking", return_value=True), patch(
        "pretix_oidc.views._finish_oidc_login"
    ) as finish_login:
        from django.http import HttpResponseRedirect

        finish_login.return_value = HttpResponseRedirect("/")
        response = OIDCLinkCompleteView.as_view()(request)

    assert response.status_code == 302
    assert get_pending_link(request) is None
    user.refresh_from_db()
    assert user.auth_backend == "pretix_oidc"
    assert user.auth_backend_identifier == "sub-linked"
    finish_login.assert_called_once()


@pytest.mark.django_db
def test_link_complete_rejects_email_mismatch():
    from django.contrib.messages.storage.fallback import FallbackStorage
    from django.urls import reverse

    from pretix_oidc.views import OIDCLinkCompleteView

    with scopes_disabled():
        user = User.objects.create_user("native@example.com", "password")

    factory = RequestFactory()
    request = factory.get(reverse("plugins:pretix_oidc:oidc_link_complete"))
    request.user = user
    request.session = {}
    setattr(request, "_messages", FallbackStorage(request))

    store_pending_link(
        request,
        {"uuid": "sub-linked", "email": "other@example.com", "fullname": "Linked"},
        {},
        {},
    )

    with patch("pretix_oidc.views.allow_account_linking", return_value=True):
        response = OIDCLinkCompleteView.as_view()(request)

    assert response.status_code == 302
    user.refresh_from_db()
    assert user.auth_backend == "native"


def test_link_choice_url_outside_control():
    from django.urls import reverse

    url = reverse("plugins:pretix_oidc:oidc_link_choice")
    assert url.startswith("/oidc/link/")
    assert not url.startswith("/control/")


def test_link_choice_accessible_without_login():
    from django.urls import reverse

    from pretix_oidc.views import OIDCLinkChoiceView

    factory = RequestFactory()
    request = factory.get(reverse("plugins:pretix_oidc:oidc_link_choice"))
    request.session = {}
    from django.contrib.auth.models import AnonymousUser

    request.user = AnonymousUser()
    store_pending_link(
        request,
        {"uuid": "sub-1", "email": "user@example.com", "fullname": "User"},
        {},
        {},
    )

    with patch("pretix_oidc.views.allow_account_linking", return_value=True):
        response = OIDCLinkChoiceView.as_view()(request)

    assert response.status_code == 200


def test_link_decline_clears_pending_link():
    from pretix_oidc.linking import get_pending_link
    from pretix_oidc.views import OIDCLinkDeclineView

    factory = RequestFactory()
    request = factory.get("/control/oidc/link/decline/")
    request.session = {}
    from django.contrib.auth.models import AnonymousUser

    request.user = AnonymousUser()
    store_pending_link(
        request,
        {"uuid": "sub-1", "email": "user@example.com", "fullname": "User"},
        {},
        {},
    )

    response = OIDCLinkDeclineView.as_view()(request)
    assert response.status_code == 200
    assert get_pending_link(request) is None


@pytest.mark.django_db
def test_dashboard_widget_only_for_native_users():
    from pretix_oidc.signals import add_oidc_link_widget

    with scopes_disabled():
        native = User.objects.create_user("native@example.com", "password")
        oidc = User.objects.create_user("oidc@example.com", "password")
        oidc.auth_backend = "pretix_oidc"
        oidc.auth_backend_identifier = "sub-1"
        oidc.save()

    factory = RequestFactory()
    request = factory.get("/")

    with patch("pretix_oidc.signals.allow_account_linking", return_value=True):
        native_widgets = add_oidc_link_widget(request, user=native)
        oidc_widgets = add_oidc_link_widget(request, user=oidc)

    assert len(native_widgets) == 1
    assert oidc_widgets == []
