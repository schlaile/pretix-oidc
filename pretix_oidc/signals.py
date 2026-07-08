from django.dispatch import receiver
from django.urls import reverse
from django.utils.translation import gettext_lazy
from pretix.control.signals import nav_organizer, user_dashboard_widgets

from .linking import allow_account_linking


@receiver(nav_organizer)
def add_team_auto_assign_to_nav_pane(sender, request, **kwargs):
    """This signal is used to add the 'Team assignment rules' column to the
    navigation pane."""
    if not request.user.is_staff:
        return []
    return [
        {
            "label": gettext_lazy("Team assignment rules"),
            "url": reverse(
                "plugins:pretix_oidc:team_assignment_rules",
                kwargs={"organizer": request.organizer.slug},
            ),
            "active": (
                getattr(request.resolver_match, "url_name", "") or ""
            ).startswith("team_assignment_rules"),
            "icon": "group",
        },
    ]


@receiver(user_dashboard_widgets)
def add_oidc_link_widget(sender, user, **kwargs):
    if not allow_account_linking() or user.auth_backend != "native":
        return []
    return [
        {
            "display_size": "small",
            "priority": 50,
            "content": gettext_lazy(
                "Connect your account for single sign-on via OpenID Connect."
            ),
            "url": reverse("plugins:pretix_oidc:oidc_link_account"),
        },
    ]
