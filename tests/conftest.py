import pytest
from django_scopes import scopes_disabled
from pretix.base.models import Organizer, Team, User

from pretix_oidc.models import OIDCTeamAssignmentRule


@pytest.fixture
def organizer_a(db):
    with scopes_disabled():
        return Organizer.objects.create(name="Organizer A", slug="orga")


@pytest.fixture
def organizer_b(db):
    with scopes_disabled():
        return Organizer.objects.create(name="Organizer B", slug="orgb")


@pytest.fixture
def team_a(organizer_a):
    with scopes_disabled():
        return Team.objects.create(
            organizer=organizer_a, name="Team A", all_events=True
        )


@pytest.fixture
def team_b(organizer_b):
    with scopes_disabled():
        return Team.objects.create(
            organizer=organizer_b, name="Team B", all_events=True
        )


@pytest.fixture
def oidc_user(db):
    with scopes_disabled():
        user = User.objects.create_user("oidc@example.com", "password")
        user.auth_backend = "pretix_oidc"
        user.auth_backend_identifier = "sub-123"
        user.save()
        return user


@pytest.fixture
def assignment_rule(team_a):
    with scopes_disabled():
        return OIDCTeamAssignmentRule.objects.create(
            team=team_a, attribute="groups", value="admin"
        )
