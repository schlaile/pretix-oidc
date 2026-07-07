import pytest
from configparser import ConfigParser
from unittest.mock import MagicMock, patch

from pretix_oidc.auth import OIDCAuthBackend


def _mock_config(**options):
    cfg = ConfigParser()
    cfg.add_section("oidc")
    defaults = {
        "issuer": "https://idp.example/",
        "authorization_endpoint": "https://idp.example/auth",
        "token_endpoint": "https://idp.example/token",
        "userinfo_endpoint": "https://idp.example/userinfo",
        "end_session_endpoint": "https://idp.example/logout",
        "jwks_uri": "https://idp.example/jwks",
        "client_id": "client",
        "client_secret": "secret",
    }
    defaults.update(options)
    for key, value in defaults.items():
        cfg.set("oidc", key, value)

    mock = MagicMock()
    mock.has_option.side_effect = cfg.has_option

    def config_get(section, option, fallback=None):
        try:
            return cfg.get(section, option)
        except Exception:
            return fallback

    mock.get.side_effect = config_get
    return mock


@pytest.mark.parametrize(
    ("scopes", "expected"),
    [
        ("openid,email,profile,groups", ["openid", "email", "profile", "groups"]),
        ("openid, email, profile, groups", ["openid", "email", "profile", "groups"]),
        ("openid", ["openid"]),
    ],
)
def test_scopes_are_trimmed(scopes, expected):
    with patch("pretix_oidc.auth.config", _mock_config(scopes=scopes)):
        backend = OIDCAuthBackend()
    assert backend.scopes == expected
