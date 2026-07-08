# pretix OIDC

This is a plugin for [pretix](https://github.com/pretix/pretix).

Forked from [thegcat/pretix-oidc](https://github.com/thegcat/pretix-oidc)

OIDC authentication plugin for pretix

## Installation

Activate the virtual environment for your pretix installation and run

    pip install pretix-oidc

To activate the OIDC authentication mechanism add
`pretix_oidc.auth.OIDCAuthBackend` to the list of `pretix.auth_backends` in
your `pretix.cfg`. Add the OIDC configuration to that same file in a new
`oidc` section, values without a default are mandatory:

    [oidc]
    # label on the login button,
    # default: Login with OpenID connect
    title=
    # OIDC URIs, can generally be found unter .well-known/openid-configuration
    # of your OIDC endpoint
    issuer=
    authorization_endpoint=
    token_endpoint=
    userinfo_endpoint=
    end_session_endpoint=
    jwks_uri=
    # OIDC client ID and secret
    client_id=
    client_secret=
    # comma-separated list of scopes to request
    # default: openid
    # recommended: openid,email,profile
    scopes=
    # what OIDC claim pretix should use to uniquely identify OIDC users
    # default: sub
    unique_attribute=
    # dot-path to a claim in the ID token for User.is_staff (legacy key: staff_scope; not an OAuth scope name)
    staff_claim=
    # comma-separated values; user becomes staff if any claim value matches. omit staff_claim and staff_value to leave staff unchanged.
    staff_value=
    # staff_value=val_1,val_2

The callback URI on your pretix will be `/oidc/callback/`, enter this at the
appropriate place in your OIDC provider.

For PocketID: use the URLs from `/.well-known/openid-configuration`, set the
callback as above, and include `groups` in `scopes` (PocketID only sends group
membership when that scope is requested). Example:

    scopes=openid,email,profile,groups

`staff_claim` and `staff_value` are optional. They set pretix system staff
(`User.is_staff`), not organizer access. Leave them out unless you want global
pretix admins matched by claim (e.g. `staff_claim=groups`,
`staff_value=pretix-admins`).

## Configuration

Organizer access is via team assignment rules, not `staff_*`. Users with
`can_change_organizer_settings` can add rules under organizer → team assignment
rules: pick a team, set the OIDC attribute (`groups` for PocketID), and the
attribute value (exact PocketID group name). Rules apply on login; matching is
add-only. Users may need to log out and back in after rule changes.

Please note that users with permission to change organizer settings can use these
rules to enumerate OIDC claim values on login, which can be a data leak.

## Development setup

1. Make sure that you have a working [pretix development
   setup](https://docs.pretix.eu/en/latest/development/setup.html).
2. Clone this repository.
3. Activate the virtual environment you use for pretix development.
4. Execute `python setup.py develop` within this directory to register
   this application with pretix\'s plugin registry.
5. Execute `make` within this directory to compile translations.
6. Restart your local pretix server. You can now use the plugin from
   this repository for your events by enabling it in the \'plugins\'
   tab in the settings.

This plugin has CI set up to enforce a few code style rules. To check
locally, you need these packages installed:

    pip install flake8 isort black

To check your plugin for rule violations, run:

    black --check .
    isort -c .
    flake8 .

You can auto-fix some of these issues by running:

    isort .
    black .

To automatically check for these issues before you commit, you can run
`.install-hooks`.

## License

Copyright 2023 Jaakko Rinta-Filppula, Felix Schäfer

Released under the terms of the Apache License 2.0
