from django.urls import path

from . import views

urlpatterns = [
    path("oidc/callback/", views.oidc_callback, name="oidc_callback"),
    path(
        "oidc/link/",
        views.OIDCLinkChoiceView.as_view(),
        name="oidc_link_choice",
    ),
    path(
        "oidc/link/auth/",
        views.OIDCLinkAuthRedirectView.as_view(),
        name="oidc_link_auth",
    ),
    path(
        "oidc/link/complete/",
        views.OIDCLinkCompleteView.as_view(),
        name="oidc_link_complete",
    ),
    path(
        "oidc/link/decline/",
        views.OIDCLinkDeclineView.as_view(),
        name="oidc_link_decline",
    ),
    path(
        "control/user/oidc-link/",
        views.OIDCLinkAccountView.as_view(),
        name="oidc_link_account",
    ),
    path(
        "control/user/oidc-link/start/",
        views.OIDCLinkStartView.as_view(),
        name="oidc_link_start",
    ),
    path(
        "control/organizer/<str:organizer>/teams/assignment_rules/",
        views.AssignmentRulesList.as_view(),
        name="team_assignment_rules",
    ),
    path(
        "control/organizer/<str:organizer>/teams/assignment_rules/add",
        views.AssignmentRuleCreate.as_view(),
        name="team_assignment_rules.add",
    ),
    path(
        "control/organizer/<str:organizer>/teams/assignment_rules/<int:pk>/edit",
        views.AssignmentRuleEdit.as_view(),
        name="team_assignment_rules.edit",
    ),
    path(
        "control/organizer/<str:organizer>/teams/assignment_rules/<int:pk>/delete",
        views.AssignmentRuleDelete.as_view(),
        name="team_assignment_rules.delete",
    ),
]
