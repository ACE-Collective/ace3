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
the preferences page. Narrowing the list to a single disposition still hides the
disposition column, as an override on top of the preference.
