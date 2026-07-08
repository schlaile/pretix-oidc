from dictlib import dig_get
from pretix.settings import config

from .models import OIDCTeamAssignmentRule


def claims_dict(source):
    """Normalize dict, pyoidc Message, or None claim sources to a plain dict."""
    if source is None:
        return {}
    if isinstance(source, dict):
        return source
    try:
        return dict(source)
    except (TypeError, ValueError):
        return {}


def is_error_response(source):
    return bool(claims_dict(source).get("error"))


def pick_claim(sources, key, default=None):
    for source in sources:
        claims = claims_dict(source)
        if not claims or claims.get("error"):
            continue
        value = claims.get(key)
        if value is not None and value != "":
            return value
    return default


def normalize_claim_values(raw):
    """Coerce claim values to comparable strings."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raw = [raw]
    return [str(v) for v in raw if v is not None and str(v) != ""]


def claim_values(claims_source, attribute, fallback_source=None):
    claims = claims_dict(claims_source)
    values = normalize_claim_values(dig_get(claims, attribute, None))
    if values:
        return values
    if fallback_source is not None and not is_error_response(fallback_source):
        return normalize_claim_values(
            dig_get(claims_dict(fallback_source), attribute, [])
        )
    return []


def add_user_to_teams(user, id_token, userinfo=None):
    """
    Add the user to teams based on OIDC team assignment rules.

    Rules are evaluated against claims in the ID token. Matching is add-only:
    a matching rule adds membership, a non-matching rule does nothing. When a
    team has multiple rules, any matching rule is sufficient (OR semantics).
    """
    rules = OIDCTeamAssignmentRule.objects.select_related(
        "team", "team__organizer"
    ).all()

    teams_by_id = {}
    for rule in rules:
        if rule.value in claim_values(id_token, rule.attribute, userinfo):
            teams_by_id[rule.team_id] = rule.team

    for team in teams_by_id.values():
        team.members.add(user)


def add_user_to_staff(user, id_token, userinfo=None):
    """
    Set User.is_staff from ID token claims configured in pretix.cfg.

    Requires staff_value plus either staff_claim or the legacy staff_scope alias
    (both are dot-paths to a claim in the ID token, not OAuth scope names).
    When configured, staff status is synced on every login (grant and revoke).
    When omitted, is_staff is left unchanged.
    """
    if not (
        (
            config.has_option("oidc", "staff_claim")
            or config.has_option("oidc", "staff_scope")
        )
        and config.has_option("oidc", "staff_value")
    ):
        return

    staff_claim = config.get("oidc", "staff_claim", fallback=None) or config.get(
        "oidc", "staff_scope", fallback=None
    )
    staff_values = [
        v.strip() for v in config.get("oidc", "staff_value").split(",") if v.strip()
    ]
    if not staff_claim or not staff_values:
        return

    values = claim_values(id_token, staff_claim, userinfo)
    user.is_staff = len(set(values) & set(staff_values)) > 0
    user.save(update_fields=["is_staff"])
