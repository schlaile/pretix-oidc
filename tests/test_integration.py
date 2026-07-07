import pytest
from django.test import RequestFactory
from django.urls import reverse
from django_scopes import scopes_disabled
from oic.oic.message import IdToken, OpenIDSchema
from pretix.base.models import User
from unittest.mock import MagicMock, patch

from pretix_oidc.assignment import claim_values
from pretix_oidc.models import OIDCTeamAssignmentRule
from pretix_oidc.views import AssignmentRulesList, oidc_callback


def test_claim_values_pyoidc_userinfo_fallback():
    id_token = IdToken(sub="643c3fba-370a-4738-92a6-9ergec96cd99")
    userinfo = OpenIDSchema(
        sub="643c3fba-370a-4738-92a6-9ergec96cd99",
        email="user@example.com",
        groups=["kubernetes"],
    )
    assert claim_values(id_token, "groups", userinfo) == ["kubernetes"]


@pytest.mark.django_db
def test_oidc_callback_failed_auth_redirects_to_control_login():
    factory = RequestFactory()
    request = factory.get("/oidc/callback/?error=access_denied")
    request.session = {}

    with patch("pretix_oidc.views.OIDCAuthBackend") as backend_cls:
        backend_cls.return_value.process_callback.return_value = [None, None, None]
        response = oidc_callback(request)

    assert response.status_code == 302
    assert response.url == reverse("control:auth.login")


@pytest.mark.django_db
def test_oidc_callback_provisions_team_membership(organizer_a, team_a, oidc_user):
    with scopes_disabled():
        OIDCTeamAssignmentRule.objects.create(
            team=team_a, attribute="groups", value="kubernetes"
        )

    factory = RequestFactory()
    request = factory.get("/oidc/callback/?code=x&state=y")
    request.session = {}

    id_token = IdToken(sub="sub-123", groups=["kubernetes"])
    userinfo = OpenIDSchema(
        sub="sub-123",
        email="oidc@example.com",
        name="OIDC User",
    )
    user_data = {
        "uuid": "sub-123",
        "email": "oidc@example.com",
        "fullname": "OIDC User",
        "auth_backend": "pretix_oidc",
    }

    with patch("pretix_oidc.views.OIDCAuthBackend") as backend_cls, patch(
        "pretix_oidc.views.process_login"
    ) as process_login:
        backend = backend_cls.return_value
        backend.identifier = "pretix_oidc"
        backend.process_callback.return_value = [user_data, id_token, userinfo]
        process_login.return_value = MagicMock(status_code=302)

        oidc_callback(request)

        process_login.assert_called_once()
        called_user = process_login.call_args[0][1]
        assert called_user.pk == oidc_user.pk

    with scopes_disabled():
        assert team_a.members.filter(pk=oidc_user.pk).exists()


@pytest.mark.django_db
def test_assignment_rules_list_includes_organizer_nav(organizer_a, team_a):
    with scopes_disabled():
        admin = User.objects.create_user("admin@example.com", "password")
        team_a.can_change_organizer_settings = True
        team_a.save(update_fields=["can_change_organizer_settings"])
        team_a.members.add(admin)

    factory = RequestFactory()
    request = factory.get(
        reverse(
            "plugins:pretix_oidc:team_assignment_rules",
            kwargs={"organizer": organizer_a.slug},
        )
    )
    request.user = admin
    request.organizer = organizer_a
    request.session = {}

    with patch(
        "pretix.control.views.organizer.nav_organizer.send",
        return_value=[(None, [{"label": "Team assignment rules", "url": "#"}])],
    ):
        response = AssignmentRulesList.as_view()(request, organizer=organizer_a.slug)

    assert response.status_code == 200
    assert "nav_organizer" in response.context_data
    assert response.context_data["organizer"] == organizer_a
