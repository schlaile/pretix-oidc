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
    # when OIDC email matches an existing native account, offer to merge (default: true)
    allow_account_linking=true
    # reject login/linking unless OIDC reports email_verified (default: true)
    require_email_verified=true

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

Organizer access is via team assignment rules, not `staff_*`. Pretix staff
(`is_staff`) can manage rules under organizer → team assignment rules: pick a
team, set the OIDC attribute (`groups` for PocketID), and the attribute value
(exact PocketID group name). Rules apply on login; matching is add-only. Users
may need to log out and back in after rule changes.

Only pretix staff can access team assignment rules. This limits who can
configure OIDC claim mappings and reduces the risk of enumerating claim values
on login.

## Account linking

Account linking (merge) is **enabled by default** (`allow_account_linking=true`).
You do not need to add this to `pretix.cfg` unless you want to change it.

If a user signs in with OpenID Connect but a native pretix account already
exists for the same email address, pretix offers to **link** the accounts
instead of creating a duplicate. Linking migrates the existing account to OIDC
(preserving teams, orders, and history).

Flow when a conflict is detected:

1. User signs in with OpenID Connect.
2. pretix shows a choice: link the existing account or decline.
3. **Link account** sends the user through the normal native login (password
   and 2FA/passkey if enabled).
4. After successful native authentication, pretix updates the user record to
   use OIDC for future logins.

If the user declines linking, they can continue with their existing login
method. To use OpenID Connect with a separate account instead, they should
change the email address on their pretix account first.

Native users can also start linking from the dashboard widget or
**Account → OpenID Connect** (`/control/user/oidc-link/`).

### Disabling account linking

To turn off merge/linking and fall back to the previous behavior (show an error
on the login page and require native username/password login), add to
`pretix.cfg`:

    [oidc]
    allow_account_linking=false

After linking, password login is disabled and OpenID Connect is required.

### Email verification

By default (`require_email_verified=true`), pretix rejects OpenID Connect logins
and account linking unless the identity provider sends `email_verified=true`
(or an equivalent truthy value) for the email claim. Explicit
`email_verified=false` is always rejected.

Include the `email` scope so your provider returns the claim. To allow logins
when the claim is missing (pretix customer SSO-compatible behavior), set:

    [oidc]
    require_email_verified=false

Verified OIDC emails also set `User.is_verified` in pretix.

### Staff merge for duplicate accounts

When a person has both a native pretix account and a separate OpenID Connect
account with different email addresses, pretix staff can merge them from the
native user detail page:

1. Open the native user in **Users**.
2. Click **Merge OpenID Connect account**.
3. Select the OpenID Connect account and confirm.

Team memberships from both accounts are combined, the native account receives
the OpenID Connect email address and becomes an OpenID Connect login, and the
duplicate OpenID Connect account is anonymized.

URL pattern: `/control/users/<native_id>/merge-oidc/`

### Switch OpenID Connect user to password login

To let a single OpenID Connect user sign in with email and password instead
(without merging into another account):

1. Open the OpenID Connect user in **Users**.
2. Click **Switch to password login (disable OIDC)**.
3. Set a new password and optionally enable **Force password change on next login**.

The same user keeps their email, teams, and history. OpenID Connect login is
disabled; they sign in with the new password from then on. The OpenID Connect
subject identifier is retained on the account so repeat OIDC sign-in attempts
are rejected with a clear message instead of failing silently.

URL pattern: `/control/users/<oidc_id>/convert-native/`

Requires an active staff session and recent re-authentication, same as
**Anonymize user**.

The merge button is injected into the pretix user detail template via the same
DATA_DIR template sync mechanism used for the combined login page. Restart
pretix after upgrading the plugin if the button does not appear immediately.

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
