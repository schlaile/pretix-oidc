import pytest
from configparser import ConfigParser
from unittest.mock import patch

from pretix_oidc.linking import (
    ensure_email_verified,
    parse_email_verified,
    require_email_verified,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, True),
        (False, False),
        ("true", True),
        ("false", False),
        ("1", True),
        ("0", False),
        (None, None),
        ("maybe", None),
    ],
)
def test_parse_email_verified(value, expected):
    assert parse_email_verified(value) is expected


@pytest.mark.parametrize(
    ("user_data", "require", "error_expected"),
    [
        ({"email_verified": True}, True, False),
        ({"email_verified": False}, True, True),
        ({"email_verified": False}, False, True),
        ({}, True, True),
        ({}, False, False),
        ({"email_verified": "true"}, True, False),
    ],
)
def test_ensure_email_verified(user_data, require, error_expected):
    with patch("pretix_oidc.linking.require_email_verified", return_value=require):
        result = ensure_email_verified(user_data)
    if error_expected:
        assert result is not None
        assert "not verified" in result.lower()
    else:
        assert result is None


def test_require_email_verified_defaults_true():
    cfg = ConfigParser()
    cfg.add_section("oidc")
    with patch(
        "pretix_oidc.linking.config.getboolean",
        side_effect=lambda section, option, fallback=None: cfg.getboolean(
            section, option, fallback=fallback
        ),
    ):
        assert require_email_verified() is True
