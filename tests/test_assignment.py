import pytest
from configparser import ConfigParser
from django.test import RequestFactory
from django_scopes import scopes_disabled
from oic.oic.message import IdToken, OpenIDSchema
from unittest.mock import MagicMock

from pretix_oidc.assignment import (
    add_user_to_staff,
    add_user_to_teams,
    claim_values,
    normalize_claim_values,
    pick_claim,
)
from pretix_oidc.models import OIDCTeamAssignmentRule
from pretix_oidc.views import AssignmentRuleDelete


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, []),
        ("admin", ["admin"]),
        (["admin", "editor"], ["admin", "editor"]),
        (123, ["123"]),
        ([123, True], ["123", "True"]),
        ([None, "", "x"], ["x"]),
    ],
)
def test_normalize_claim_values(raw, expected):
    assert normalize_claim_values(raw) == expected


def test_claim_values_scalar_and_list():
    token = {"groups": "admin"}
    assert claim_values(token, "groups") == ["admin"]

    token = {"groups": ["admin", "editor"]}
    assert claim_values(token, "groups") == ["admin", "editor"]


def test_claim_values_nested_path():
    token = {"realm_access": {"roles": ["staff", "user"]}}
    assert claim_values(token, "realm_access.roles") == ["staff", "user"]


def test_claim_values_pyoidc_id_token():
    token = IdToken(sub="x", groups=["kubernetes", "admins"])
    assert claim_values(token, "groups") == ["kubernetes", "admins"]


def test_claim_values_userinfo_fallback():
    id_token = {"sub": "x"}
    userinfo = {"groups": ["kubernetes"]}
    assert claim_values(id_token, "groups", userinfo) == ["kubernetes"]


def test_claim_values_id_token_takes_precedence_over_userinfo():
    id_token = {"groups": ["from-id-token"]}
    userinfo = {"groups": ["from-userinfo"]}
    assert claim_values(id_token, "groups", userinfo) == ["from-id-token"]


def test_pick_claim_falls_back_to_id_token():
    id_token = IdToken(
        sub="b5f5e7d5-5f48-4bca-88ff-9591bdfcf4ad",
        email="daniel@binary.management",
        name="Daniel Malik",
        pretix_organizer="binary",
    )
    userinfo = OpenIDSchema(email="daniel@binary.management", name="Daniel Malik")
    assert pick_claim([userinfo, id_token], "sub") == "b5f5e7d5-5f48-4bca-88ff-9591bdfcf4ad"
    assert pick_claim([userinfo, id_token], "pretix_organizer") == "binary"


def test_pocket_id_organizer_claim_in_id_token_only(oidc_user, team_a):
    with scopes_disabled():
        OIDCTeamAssignmentRule.objects.create(
            team=team_a, attribute="pretix_organizer", value="binary"
        )

    id_token = IdToken(
        sub="b5f5e7d5-5f48-4bca-88ff-9591bdfcf4ad",
        pretix_organizer="binary",
    )
    userinfo = OpenIDSchema(
        email="daniel@binary.management",
        name="Daniel Malik",
    )
    add_user_to_teams(oidc_user, id_token, userinfo)

    with scopes_disabled():
        assert team_a.members.filter(pk=oidc_user.pk).exists()


def test_staff_claim_falls_back_to_userinfo(oidc_user, monkeypatch):
    cfg = ConfigParser()
    cfg.add_section("oidc")
    cfg.set("oidc", "staff_claim", "groups")
    cfg.set("oidc", "staff_value", "admin")

    mock_config = MagicMock()
    mock_config.has_option.side_effect = cfg.has_option
    mock_config.get.side_effect = cfg.get
    monkeypatch.setattr("pretix_oidc.assignment.config", mock_config)

    oidc_user.is_staff = False
    oidc_user.save(update_fields=["is_staff"])

    add_user_to_staff(oidc_user, {"sub": "x"}, {"groups": ["admin"]})

    with scopes_disabled():
        oidc_user.refresh_from_db()
        assert oidc_user.is_staff is True


def test_authentik_groups_in_id_token(oidc_user, team_a):
    with scopes_disabled():
        OIDCTeamAssignmentRule.objects.create(
            team=team_a, attribute="groups", value="authentik Admins"
        )

    id_token = {
        "sub": "user-1",
        "email": "user@example.com",
        "name": "Example User",
        "groups": ["authentik Admins", "admins"],
    }
    add_user_to_teams(oidc_user, id_token)

    with scopes_disabled():
        assert team_a.members.filter(pk=oidc_user.pk).exists()


def test_pocket_id_groups_in_id_token(oidc_user, team_a):
    with scopes_disabled():
        OIDCTeamAssignmentRule.objects.create(
            team=team_a, attribute="groups", value="kubernetes"
        )

    id_token = {
        "sub": "643c3fba-370a-4738-92a6-9ergec96cd99",
        "email": "user@example.com",
        "groups": ["kubernetes"],
    }
    add_user_to_teams(oidc_user, id_token)

    with scopes_disabled():
        assert team_a.members.filter(pk=oidc_user.pk).exists()


def test_pocket_id_groups_from_userinfo_when_missing_in_id_token(oidc_user, team_a):
    with scopes_disabled():
        OIDCTeamAssignmentRule.objects.create(
            team=team_a, attribute="groups", value="kubernetes"
        )

    add_user_to_teams(oidc_user, {"sub": "x"}, {"groups": ["kubernetes"]})

    with scopes_disabled():
        assert team_a.members.filter(pk=oidc_user.pk).exists()


def test_team_add_on_matching_rule(oidc_user, team_a, assignment_rule):
    add_user_to_teams(oidc_user, {"groups": ["admin"]})

    with scopes_disabled():
        assert team_a.members.filter(pk=oidc_user.pk).exists()


def test_team_add_only_no_remove(oidc_user, team_a, assignment_rule):
    with scopes_disabled():
        team_a.members.add(oidc_user)

    add_user_to_teams(oidc_user, {"groups": ["other"]})

    with scopes_disabled():
        assert team_a.members.filter(pk=oidc_user.pk).exists()


def test_team_multi_rule_or_semantics(oidc_user, team_a):
    with scopes_disabled():
        OIDCTeamAssignmentRule.objects.create(
            team=team_a, attribute="groups", value="admin"
        )
        OIDCTeamAssignmentRule.objects.create(
            team=team_a, attribute="groups", value="editor"
        )

    add_user_to_teams(oidc_user, {"groups": ["admin"]})

    with scopes_disabled():
        assert team_a.members.filter(pk=oidc_user.pk).exists()


def test_team_multi_rule_no_false_remove(oidc_user, team_a):
    with scopes_disabled():
        OIDCTeamAssignmentRule.objects.create(
            team=team_a, attribute="groups", value="admin"
        )
        OIDCTeamAssignmentRule.objects.create(
            team=team_a, attribute="groups", value="editor"
        )

    add_user_to_teams(oidc_user, {"groups": ["admin"]})

    with scopes_disabled():
        assert team_a.members.filter(pk=oidc_user.pk).exists()


def test_claim_type_coercion(oidc_user, team_a):
    with scopes_disabled():
        OIDCTeamAssignmentRule.objects.create(
            team=team_a, attribute="org_id", value="123"
        )

    add_user_to_teams(oidc_user, {"org_id": 123})

    with scopes_disabled():
        assert team_a.members.filter(pk=oidc_user.pk).exists()


def test_staff_claim_intersection(oidc_user, monkeypatch):
    cfg = ConfigParser()
    cfg.add_section("oidc")
    cfg.set("oidc", "staff_claim", "groups")
    cfg.set("oidc", "staff_value", "staff, admin")

    mock_config = MagicMock()
    mock_config.has_option.side_effect = cfg.has_option
    mock_config.get.side_effect = cfg.get
    monkeypatch.setattr("pretix_oidc.assignment.config", mock_config)

    oidc_user.is_staff = False
    oidc_user.save(update_fields=["is_staff"])

    add_user_to_staff(oidc_user, {"groups": ["user", "staff"]})

    with scopes_disabled():
        oidc_user.refresh_from_db()
        assert oidc_user.is_staff is True


def test_staff_omit_config(oidc_user, monkeypatch):
    mock_config = MagicMock()
    mock_config.has_option.return_value = False
    monkeypatch.setattr("pretix_oidc.assignment.config", mock_config)

    oidc_user.is_staff = True
    oidc_user.save(update_fields=["is_staff"])

    add_user_to_staff(oidc_user, {"groups": ["staff"]})

    with scopes_disabled():
        oidc_user.refresh_from_db()
        assert oidc_user.is_staff is True


def test_staff_legacy_scope_alias(oidc_user, monkeypatch):
    cfg = ConfigParser()
    cfg.add_section("oidc")
    cfg.set("oidc", "staff_scope", "groups")
    cfg.set("oidc", "staff_value", "admin")

    mock_config = MagicMock()
    mock_config.has_option.side_effect = cfg.has_option
    mock_config.get.side_effect = cfg.get
    monkeypatch.setattr("pretix_oidc.assignment.config", mock_config)

    oidc_user.is_staff = False
    oidc_user.save(update_fields=["is_staff"])

    add_user_to_staff(oidc_user, {"groups": ["admin"]})

    with scopes_disabled():
        oidc_user.refresh_from_db()
        assert oidc_user.is_staff is True


def test_delete_queryset_scoped(organizer_a, organizer_b, team_a, team_b):
    with scopes_disabled():
        rule_a = OIDCTeamAssignmentRule.objects.create(
            team=team_a, attribute="groups", value="a"
        )
        rule_b = OIDCTeamAssignmentRule.objects.create(
            team=team_b, attribute="groups", value="b"
        )

    factory = RequestFactory()
    request = factory.get("/")
    request.organizer = organizer_a

    view = AssignmentRuleDelete()
    view.request = request
    queryset = view.get_queryset()

    assert rule_a in queryset
    assert rule_b not in queryset
