from unittest.mock import MagicMock

from pretix_oidc.templatetags.pretix_oidc_auth import (
    external_auth_backends,
    oidc_login_error,
    show_native_external_auth,
)


def _backend(identifier, url=None, visible=True):
    backend = MagicMock()
    backend.identifier = identifier
    backend.url = url
    backend.visible = visible
    return backend


def test_external_auth_backends_filters_native_and_urlless():
    backends = [
        _backend("native"),
        _backend("pretix_oidc", url="https://idp.example/auth"),
        _backend("other", url=None),
        _backend("hidden", url="https://idp.example/hidden", visible=False),
    ]

    result = external_auth_backends(backends)

    assert len(result) == 1
    assert result[0].identifier == "pretix_oidc"


def test_show_native_external_auth_hides_when_backend_native_in_query():
    request = MagicMock()
    request.GET = {"backend": "native", "next": "/oidc/link/complete/"}
    backend = _backend("native")
    external = [_backend("pretix_oidc", url="https://idp.example/auth")]

    assert show_native_external_auth(request, backend, external) is False


def test_show_native_external_auth_shows_on_default_native_login():
    request = MagicMock()
    request.GET = {}
    backend = _backend("native")
    external = [_backend("pretix_oidc", url="https://idp.example/auth")]

    assert show_native_external_auth(request, backend, external) is True


def test_show_native_external_auth_stays_visible_for_oidc_error():
    request = MagicMock()
    request.GET = {"oidc_error": "state_mismatch"}
    backend = _backend("native")
    external = [_backend("pretix_oidc", url="/oidc/login/")]

    assert show_native_external_auth(request, backend, external) is True


def test_oidc_login_error_renders_retryable_reason():
    request = MagicMock()
    request.GET = {"oidc_error": "state_mismatch"}

    message = oidc_login_error(request)

    assert "expired or was interrupted" in str(message)


def test_oidc_login_error_empty_without_reason():
    request = MagicMock()
    request.GET = {}

    assert oidc_login_error(request) == ""


def test_login_template_reloads_when_restored_from_cache():
    from pathlib import Path

    import pretix_oidc

    template = (
        Path(pretix_oidc.__file__).parent / "templates/pretixcontrol/auth/login.html"
    ).read_text()

    assert 'pageshow' in template
    assert "event.persisted" in template
    assert "oidc_login_error" in template
