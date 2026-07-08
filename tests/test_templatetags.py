from unittest.mock import MagicMock

from pretix_oidc.templatetags.pretix_oidc_auth import external_auth_backends


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
