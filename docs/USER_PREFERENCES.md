# User preferences

A **preference** is a durable per-user GUI setting: something an analyst configures once
and expects to keep across browsers and logins. Which columns the alert list shows, and
in what order, is the first one. **View state** is different: sort order, page offset,
the checked rows and the active search are transient, belong to one tab's session, and
stay in the Flask session cookie. Do not put a preference in the cookie (it is
per-browser and dies with the browser session) and do not put view state in the
preferences table (two tabs would fight over it).

## Storage and API

Preferences live in the `user_preferences` table (`saq/database/model.py::UserPreference`):
one row per user and key, the value JSON-serialized. They are owned by
`aceapi_v2/user_preferences/` and served under the caller's own account:

| Method | Path | Meaning |
|---|---|---|
| `GET` | `/api/v2/users/me/preferences` | every registered preference, defaults filled in |
| `GET` | `/api/v2/users/me/preferences/{key}` | one preference (`is_default` says whether it is stored) |
| `PUT` | `/api/v2/users/me/preferences/{key}` | replace the value; the body is the value itself |
| `DELETE` | `/api/v2/users/me/preferences/{key}` | forget the stored value so the default applies |

The user id comes from the auth result, never the request, and no permission grant beyond
being authenticated as a user is required. The GUI's pages **change** a preference by
calling this API from the browser (same origin, Flask session cookie), and **render** from
one through `app/user_preferences.py`, which reads it over the sync bridge.

The same rule covers the profile fields a user may edit themselves: `GET`/`PATCH
/api/v2/users/me` accepts display name, timezone and default queue, and `GET
/api/v2/users/me/apikeys` lists the caller's own keys. Username, email, password and
enablement stay with the admin endpoints.

These routes are gated by `require_self_service()` (`aceapi_v2/dependencies.py`) rather
than `require_permission()`. It checks no grant -- being the user *is* the authorization --
but it does still enforce the credential's scope: a **scoped** API key is refused, because
"manage my owner's account" is not something a `major:minor` scope can name. Credentials
that carry no scope pass, which is the session cookie and any key minted with `inherit`.
Without that check a self-service route would be reachable by every authenticated key
whatever its scope; `tests/saq/test_permission_catalog.py::TestRouteCoverage` pins the
whole self-service surface so a new `/users/me` route cannot land ungated.

### Your own API keys

A user holding `user:self` creates, edits and revokes their own keys on the preferences
page, without `user:write`:

| Method | Path | |
|---|---|---|
| `POST` | `/api/v2/users/me/apikeys` | mint a key (*201*, `Cache-Control: no-store`); the plaintext is returned once |
| `PUT` | `/api/v2/users/me/apikeys/{key_id}` | rename a key and replace its scope; another user's key is a 404 |
| `DELETE` | `/api/v2/users/me/apikeys/{key_id}` | revoke a key; `revoked` is false for a missing key and for another user's |

- **Gates.** These routes need `user:self` and a GUI session (`require_self_service(session_only=True)`). No API key is accepted, not even one minted with `inherit`, so a leaked key cannot leave new credentials behind that outlive its revocation.
- **Scoped keys only.** There is no `inherit` field (`ApiKeySelfWrite`); only an admin mints a key with full account access.
- **Only what you hold.** Each pattern in the scope must cover at least one permission in the catalog, and every permission it covers must be one the user holds (`_check_scope_within_grants` in `aceapi_v2/users/service.py`). `signature:*` is accepted for a user who holds every `signature` permission. `*:*` is refused for a user denied anything, since it covers what they are denied. An edit is held to the same rule over the whole scope, so a pattern the user no longer holds, or one an admin put there, has to be removed before the key can be saved.
- **Request time still decides.** A key's scope is intersected with its owner's live grants on every request. A permission the user loses stops working for every key that names it at once; the entry stays on the key but allows nothing, and works again if the permission is granted back.

Any group granted `*:*` holds `user:self` too. Its members can mint keys for any API permission they hold, `ai:*` and `engine:*` included, which before only an admin could put on a key. Deny `user:self`, or the permissions that should not be reachable with a key, where that is not wanted. A user without `user:read` sees no other user on Admin > Users, but still manages their own keys here.

## Adding a preference

Every key is registered in `PREFERENCE_SCHEMAS` in `aceapi_v2/user_preferences/schemas.py`
with the Pydantic model that validates and normalizes its value. That model is the single
gate for the API, for the Flask views that read the value back, and for the default a user
without a stored row gets -- so a stale stored value (a column id a later release
removed) is repaired the same way on every path, and an unreadable row falls back to the
default with a warning rather than taking the page down.

1. Write the model. Give every field a default so `Model()` is the preference's default,
   and put any normalization in validators (with `validate_default=True` on a field whose
   validator has to run on the default too).
2. Add it to `PREFERENCE_SCHEMAS`.
3. Read it where the page renders (`app/user_preferences.py` has the manage-columns
   helper to copy) and write it from the page's JavaScript.
4. Give it a control on the preferences page (`app/templates/preferences.html`, served by
   `main.preferences`) if it is something an analyst would set outside the page it applies
   to.

## The alert list columns

`saq/gui/manage_columns.py` declares every column the alert table can show, in default
order, with its label, sort key, and whether it is required (the description column can be
moved but never hidden). The `manage_columns` preference is `{order: [ids], hidden: [ids]}`
-- two lists rather than one list of visible columns, so that a column added in a later
release is distinguishable from one the analyst hid and shows up for everyone.

`app/templates/analysis/_manage_alert_table.html` loops over the analyst's visible
columns and renders each through the macros in `_manage_columns.html`; adding a column
means a `ColumnSpec` in the registry and a branch in each macro, and
`tests/saq/gui/test_manage_columns.py` checks the two agree. The column chooser
(`_manage_column_chooser.html` + `js/manage_columns.js`) is shared by the manage page and
the preferences page. The filters never change which columns are shown: the disposition
column stays visible when the list is narrowed to one disposition.

## The theme

The `theme` preference is `{mode: "system" | "light" | "dark" | "jd" | "halloween"}`,
`system` by default. `system` follows the operating system's light or dark setting, and `jd`
(shown as 👴 JD) is a high-contrast light mode: black on white, every color at WCAG AAA
contrast, underlined links and slightly larger text. `halloween` (🎃 Halloween) is a dark
mode: pumpkin orange on midnight purple, a moonlit glow, a jack-o'-lantern in place of the
logo and a cobweb in the navbar's corner.

`core.html` renders the mode on the root element as `data-ace-theme`, and Bootstrap's own
`data-bs-theme` as `light` or `dark` (`jd` is `light`, `halloween` is `dark`). A mode that
builds on light or dark, like these two, redefines only what differs under its
`[data-ace-theme=...]` block in `saq.css`, after the palette it builds on: the dark
palette derives its subtle shades from its base colors, so Halloween sets only those. A new
mode is added to `ThemePreference`, `THEME_CHOICES` and both places in `core.html` that pick
`data-bs-theme`. Only the browser knows the OS
setting, so a small inline script in `<head>`, ahead of every stylesheet, resolves
`system` from `prefers-color-scheme` before the first paint and follows the OS if it
changes while the page is open. The same script defines `aceApplyTheme(mode)`, which the
navbar's theme menu and the preferences page's Appearance card call through
`save_theme()` (`js/ace.js`) to switch at once before storing the choice. The lookup is
the `ui_theme()` template callable (`app/application.py`), memoized per render, so a page
reads the preference once and a fragment never does.

Writing GUI CSS that works in every theme:

- Use Bootstrap's variables (`--bs-body-bg`, `--bs-tertiary-bg`, `--bs-border-color`,
  `--bs-secondary-color`, `--bs-emphasis-color`, ...) and its theme-aware utilities
  (`bg-body`, `bg-body-tertiary`, `text-body-emphasis`, `text-bg-warning`), never a
  literal color.
- A color ACE chooses itself (the observable type colors, the JSON viewer) is an
  `--ace-*` token at the top of `static/css/saq.css`, defined for light and redefined
  under `[data-bs-theme=dark]` and, when the light value is below 7:1, `[data-ace-theme=jd]`.
- Dark mode has its own palette rather than Bootstrap's: warm neutral grays, softer white
  text, and theme colors (primary, secondary, success, warning, danger) light enough that
  text in them reads at 4.5:1 or better on the page. It redefines Bootstrap's variables
  under `[data-bs-theme=dark]` at the top of `saq.css`, so anything built on those
  variables follows it. A fill in one of the theme colors (a primary button, a
  `text-bg-secondary` tag, an active pill) carries dark text.
- Bootstrap 5.3 fixes some classes to light-mode colors in every color mode: `bg-white`,
  `bg-light`, `text-bg-light`, `text-dark`, `border-dark`, `border-black`, the contextual
  table colors (`table-success`, `table-secondary`, ...), and the colored buttons, badges and
  active states, which keep `#0d6efd` or `#dc3545` with white text. They also arrive from
  integration templates and from class names built in config (a disposition's `css: light`)
  and Python, so rather than banning them, `saq.css` maps each onto the dark palette, and
  `tests/app/test_light_only_classes.py` keeps that list covered. A literal color in a
  `style` attribute has no such fallback.
- Dark overrides for the vendored jQuery UI and date picker styles live in `saq.css`, not
  in the vendor files.
