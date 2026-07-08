import pytest
from configparser import ConfigParser
from oic.oic.message import IdToken, OpenIDSchema
from unittest.mock import MagicMock, patch

from pretix_oidc.auth import OIDCAuthBackend

POCKETID_SUB = "b5f5e7d5-5f48-4bca-88ff-9591bdfcf4ad"
POCKETID_EMAIL = "daniel@binary.management"
POCKETID_NAME = "Daniel Malik"
POCKETID_ORGANIZER = "binary"


def _pocketid_id_token(**overrides):
    defaults = {
        "sub": POCKETID_SUB,
        "email": POCKETID_EMAIL,
        "name": POCKETID_NAME,
        "pretix_organizer": POCKETID_ORGANIZER,
    }
    defaults.update(overrides)
    return IdToken(**defaults)


def _pocketid_userinfo_no_sub(**overrides):
    defaults = {"email": POCKETID_EMAIL, "name": POCKETID_NAME}
    defaults.update(overrides)
    return OpenIDSchema(**defaults)


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


def _callback_backend(id_token, userinfo, *, access_token_response=None):
    with patch("pretix_oidc.auth.config", _mock_config()):
        backend = OIDCAuthBackend()

    backend.client = MagicMock()
    backend.redirect_uri = MagicMock(return_value="https://pretix.example/oidc/callback/")
    backend.client.parse_response.return_value = {"state": "state-1", "code": "code-1"}
    if access_token_response is None:
        access_token_response = {"id_token": id_token}
    backend.client.do_access_token_request.return_value = access_token_response
    backend.client.do_user_info_request.return_value = userinfo

    request = MagicMock()
    request.META = {"QUERY_STRING": "code=code-1&state=state-1"}
    request.session = {
        "oidc_state": {"state-1": {"next": None, "generated_on": 9999999999}}
    }
    return backend, request


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


def test_process_callback_falls_back_to_id_token_for_sub_email_name():
    id_token = _pocketid_id_token()
    userinfo = _pocketid_userinfo_no_sub()

    backend, request = _callback_backend(id_token, userinfo)
    user_data, normalized_id_token, normalized_userinfo = backend.process_callback(request)

    assert user_data == {
        "uuid": POCKETID_SUB,
        "email": POCKETID_EMAIL,
        "fullname": POCKETID_NAME,
        "auth_backend": "pretix_oidc",
    }
    assert normalized_id_token["pretix_organizer"] == POCKETID_ORGANIZER
    assert "sub" not in normalized_userinfo


def test_process_callback_empty_userinfo_valid_id_token():
    id_token = _pocketid_id_token()
    userinfo = OpenIDSchema()

    backend, request = _callback_backend(id_token, userinfo)
    user_data, normalized_id_token, normalized_userinfo = backend.process_callback(request)

    assert user_data["uuid"] == POCKETID_SUB
    assert user_data["email"] == POCKETID_EMAIL
    assert user_data["fullname"] == POCKETID_NAME
    assert normalized_id_token["sub"] == POCKETID_SUB
    assert normalized_userinfo == {}


def test_process_callback_ignores_userinfo_error_and_uses_id_token():
    id_token = _pocketid_id_token()
    userinfo = OpenIDSchema(error="access_denied")

    backend, request = _callback_backend(id_token, userinfo)
    user_data, normalized_id_token, normalized_userinfo = backend.process_callback(request)

    assert user_data["uuid"] == POCKETID_SUB
    assert user_data["email"] == POCKETID_EMAIL
    assert normalized_id_token["sub"] == POCKETID_SUB
    assert normalized_userinfo == {}


def test_process_callback_rejects_missing_email():
    id_token = IdToken(sub=POCKETID_SUB)
    userinfo = OpenIDSchema(sub=POCKETID_SUB)

    backend, request = _callback_backend(id_token, userinfo)
    assert backend.process_callback(request) == [None, None, None]


def test_process_callback_rejects_missing_uuid():
    id_token = IdToken(email=POCKETID_EMAIL, name=POCKETID_NAME)
    userinfo = OpenIDSchema(email=POCKETID_EMAIL, name=POCKETID_NAME)

    backend, request = _callback_backend(id_token, userinfo)
    assert backend.process_callback(request) == [None, None, None]


def test_process_callback_rejects_missing_id_token():
    backend, request = _callback_backend(
        _pocketid_id_token(),
        OpenIDSchema(),
        access_token_response={},
    )
    assert backend.process_callback(request) == [None, None, None]
