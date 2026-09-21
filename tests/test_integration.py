import pytest
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.test import RequestFactory
from django.urls import reverse
from django_scopes import scopes_disabled
from oic.oic.message import IdToken, OpenIDSchema
from pretix.base.models import User
from unittest.mock import MagicMock, patch

from pretix_oidc.assignment import claim_values
from pretix_oidc.models import OIDCTeamAssignmentRule
from pretix_oidc.signals import add_team_auto_assign_to_nav_pane
from pretix_oidc.views import AssignmentRuleEdit, AssignmentRulesList, oidc_callback


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

    with patch("pretix_oidc.views.OIDCAuthBackend") as backend_cls, patch(
        "pretix_oidc.views.messages"
    ) as msg_mock:
        backend_cls.return_value.process_callback.return_value = [None, None, None]
        response = oidc_callback(request)

    assert response.status_code == 302
    assert response.url == reverse("control:auth.login") + "?oidc_error=failed"
    assert "backend=native" not in response.url
    msg_mock.error.assert_not_called()


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
        "email_verified": True,
        "auth_backend": "pretix_oidc",
    }

    with patch("pretix_oidc.views.OIDCAuthBackend") as backend_cls, patch(
        "pretix_oidc.views.process_login"
    ) as process_login:
        backend = backend_cls.return_value
        backend.identifier = "pretix_oidc"
        backend.process_callback.return_value = [user_data, id_token, userinfo]
        process_login.return_value = HttpResponseRedirect("/control/")

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
        admin.is_staff = True
        admin.save(update_fields=["is_staff"])
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


@pytest.mark.django_db
def test_assignment_rules_list_denied_for_non_staff(organizer_a, team_a):
    with scopes_disabled():
        user = User.objects.create_user("user@example.com", "password")
        team_a.can_change_organizer_settings = True
        team_a.save(update_fields=["can_change_organizer_settings"])
        team_a.members.add(user)

    factory = RequestFactory()
    request = factory.get(
        reverse(
            "plugins:pretix_oidc:team_assignment_rules",
            kwargs={"organizer": organizer_a.slug},
        )
    )
    request.user = user
    request.organizer = organizer_a
    request.session = {}

    with pytest.raises(PermissionDenied):
        AssignmentRulesList.as_view()(request, organizer=organizer_a.slug)


@pytest.mark.django_db
def test_assignment_rules_nav_visible_only_for_staff(organizer_a, team_a):
    factory = RequestFactory()

    staff_request = factory.get("/")
    staff_request.user = MagicMock(is_staff=True)
    staff_request.organizer = organizer_a
    staff_request.resolver_match = MagicMock(url_name="team_assignment_rules")

    non_staff_request = factory.get("/")
    non_staff_request.user = MagicMock(is_staff=False)
    non_staff_request.organizer = organizer_a
    non_staff_request.resolver_match = MagicMock(url_name="")

    staff_nav = add_team_auto_assign_to_nav_pane(None, staff_request)
    non_staff_nav = add_team_auto_assign_to_nav_pane(None, non_staff_request)

    assert len(staff_nav) == 1
    assert staff_nav[0]["label"] == "Team assignment rules"
    assert non_staff_nav == []


@pytest.mark.django_db
def test_assignment_rule_edit_form_saves(organizer_a, team_a, assignment_rule):
    from pretix_oidc.forms import OIDCAssignmentRuleForm

    with scopes_disabled():
        form = OIDCAssignmentRuleForm(
            organizer=organizer_a,
            data={"team": team_a.pk, "attribute": "roles", "value": "editor"},
            instance=assignment_rule,
        )
        assert form.is_valid(), form.errors
        form.save()
        assignment_rule.refresh_from_db()
        assert assignment_rule.attribute == "roles"
        assert assignment_rule.value == "editor"


@pytest.mark.django_db
def test_assignment_rule_edit_view_get(organizer_a, team_a, assignment_rule):
    with scopes_disabled():
        staff = User.objects.create_user("staff@example.com", "password")
        staff.is_staff = True
        staff.save(update_fields=["is_staff"])

    factory = RequestFactory()
    edit_url = reverse(
        "plugins:pretix_oidc:team_assignment_rules.edit",
        kwargs={"organizer": organizer_a.slug, "pk": assignment_rule.pk},
    )

    get_request = factory.get(edit_url)
    get_request.user = staff
    get_request.organizer = organizer_a
    get_request.session = {}

    with patch(
        "pretix.control.views.organizer.nav_organizer.send",
        return_value=[],
    ):
        get_response = AssignmentRuleEdit.as_view()(
            get_request, organizer=organizer_a.slug, pk=assignment_rule.pk
        )
    assert get_response.status_code == 200
    assert get_response.context_data["rule"].pk == assignment_rule.pk

    post_request = factory.post(
        edit_url,
        {"team": team_a.pk, "attribute": "roles", "value": "editor"},
    )
    post_request.user = staff
    post_request.organizer = organizer_a
    post_request.session = {}
    setattr(post_request, "_messages", FallbackStorage(post_request))

    with patch(
        "pretix.control.views.organizer.nav_organizer.send",
        return_value=[],
    ):
        post_response = AssignmentRuleEdit.as_view()(
            post_request, organizer=organizer_a.slug, pk=assignment_rule.pk
        )
    assert post_response.status_code == 302
    assert post_response.url == reverse(
        "plugins:pretix_oidc:team_assignment_rules",
        kwargs={"organizer": organizer_a.slug},
    )

    with scopes_disabled():
        assignment_rule.refresh_from_db()
        assert assignment_rule.attribute == "roles"
        assert assignment_rule.value == "editor"
