# Flask → FastAPI (`aceapi_v2/`) Migration

Playbook and progress tracker for moving Flask endpoints to the FastAPI implementation in `aceapi_v2/`. Update it in the same change as each migration.

The FastAPI app is served under `/api/v2`. Nothing else under `/api` is served: the legacy Flask API (`aceapi/`, served under `/api` by its own `http-api` container) is deleted.

This doc tracks three surfaces:
1. The legacy **`aceapi/` JSON API** (consumed by the `ace_api.py` client) — the original migration scope. Finished: every route is migrated or deleted, see [Already migrated](#already-migrated).
2. **`app/` GUI routes that return a machine-readable payload** (JSON / CSV / file / data) rather than a rendered template — these are *also* fair game for FastAPI, following the precedent set when `export_events_to_csv` was lifted out of the `app/events/views/` GUI blueprint during the `/events` migration. See [Flask GUI routes (`app/`) — non-template migration candidates](#flask-gui-routes-app--non-template-migration-candidates) at the end.
3. **Routes in an integration's Flask blueprint** (`integrations/<name>/src/<package>/app/`). They move to a router in the integration, served under `/api/v2/integrations/<name>`. See [Integration routes](#integration-routes).

---

## Summary

| Blueprint  | File          | Endpoints | Methods        | Status     |
|------------|---------------|-----------|----------------|------------|
| `common`   | _(removed)_   | –         | –              | Migrated   |
| `events`   | _(removed)_   | –         | –              | Migrated   |
| `email`    | _(removed)_   | –         | –              | Migrated   |
| `intel`    | _(removed)_   | –         | –              | Deleted    |
| `analysis` | _(removed)_   | –         | –              | Migrated   |
| `engine`   | _(removed)_   | –         | –              | Migrated   |
| `hunt`     | _(removed)_   | –         | –              | Migrated   |

**Legacy endpoints remaining: 0.** `aceapi/`, `api_uwsgi.py`, the `http-api` container and its nginx `/api` location are deleted.

GUI routes (`app/`): **no API-shaped candidates left** out of 82 routes; see [the GUI section](#flask-gui-routes-app--non-template-migration-candidates).

Integration blueprints: the example integration's one data route is migrated (see [its appendix entry](#integration-routes--apiv2integrationsname)). Integrations kept in other repositories migrate in their own; the playbook is [Integration routes](#integration-routes).

Defects found in routes that have not migrated yet are listed under [Known defects](#known-defects-in-unmigrated-routes), for a separate fix.

### What is left

Nothing in `aceapi/`. The GUI's remaining Flask routes render pages or are session glue (see [the GUI section](#flask-gui-routes-app--non-template-migration-candidates)), and integrations kept in other repositories migrate in their own. Check whether anything still calls a route before scheduling its port (see [Check for callers first](#check-for-callers-first)).

---

## Migration playbook

A migration moves a blueprint's endpoints from Flask to FastAPI. This is a **full replacement**: the Flask routes and their module are deleted, and every caller (Python `ace_api` client, Flask-UI views, JavaScript) is updated in the same change. Do not keep Flask routes as shims.

### Check for callers first

A route nothing calls is deleted, not ported. Before designing a v2 replacement, check both sides:

- **In the tree:** grep every checkout (this repo, `integrations/`, `signatures/`, and other repos that may call ACE) for the URL path, the `ace_api` helper and any CLI subcommand built on it. A helper whose only callers are its own CLI wrapper and its own tests is not evidence of use.
- **In production:** the reverse proxy's access log has the request path of every call. Count requests to the route over the log's whole retention, and run the same search for a route you know is busy, so that zero hits mean "unused" rather than "not logged".
- **When there is traffic, find the caller** before porting for it: the log line's user agent and client address say whether it is ACE itself (a node, a collector) or someone's script, and the git history of every repo that could hold the caller says whether it has since moved to another API. Traffic that stopped weeks ago is usually a caller that already moved.

What decides the cost of a migration is less the handler than who calls it. Three kinds of caller need different care:

- **In-process only** (`ace_api` helper, called by nothing in the tree but its tests): the cheapest. The library's external consumers see no change as long as the helper keeps its return shape.
- **Node to node** (`engine`, and `ace_api.upload`/`submit` aimed at a remote node): one ACE node calls another. During a rolling upgrade the caller can be on the new code while the node it calls is still on the old, so a v2 path that only one side has turns into a 404 for as long as the window lasts. A full replacement here needs either an all-nodes-at-once deploy or one release in which the new caller falls back to the old path.
- **Separately installed clients** (`hunt/validate` from the `validate-hunt` CLI): installed copies keep calling the old URL until they are upgraded, so the server change and the client release have to be sequenced (see [the `/hunt/validate` entry](#huntvalidate--aceapi_v2hunt)).

`/intel` and five of the six `/analysis` reads were removed this way (see the [`/intel`](#intel--deleted-alert-page-detection-actions--aceapi_v2detection) and [`/analysis` reads](#analysis-reads--deleted-ace_apiget_analysis--get-apiv2alertsuuid) appendix entries): nothing called them, and porting them would have cost more than any migration so far.

### URL naming

HTTP verbs already carry intent — drop `get_*` / `set_*` / `_endpoint` prefixes from new route paths. Use resource nouns.

| Legacy Flask URL                    | v2 URL                          |
|-------------------------------------|---------------------------------|
| `GET /common/get_valid_companies`   | `GET /common/valid_companies`   |
| `POST /analysis/submit`             | `POST /analysis/` (or similar)  |
| `PUT /events/<id>/status`           | `PATCH /events/<id>` (optional) |

### Module layout

```
aceapi_v2/<group>/
  __init__.py      # one-line docstring
  router.py        # APIRouter + endpoint handlers (async)
  service.py       # async service functions (first arg: AsyncSession, if needed)
  schemas.py       # Pydantic BaseModel request/response schemas
```

### Router conventions

- Router-level: `APIRouter(dependencies=[Security(get_current_auth)])` — every route requires some valid credential (API key, JWT, or Flask session cookie).
- **Every route carries a gate**, reads included: `auth: Annotated[ApiAuthResult, Depends(require_permission("<major>", "<minor>"))]`, or `require_self_service()` for routes that act only on the caller's own account, or `require_screen_permission()` for routes whose permission depends on the filter screen they name (all in `aceapi_v2/dependencies.py`). The router-level `get_current_auth` only authenticates; the gate is what applies an API key's scope, so an ungated route is reachable by any key whatever its scope. `tests/saq/test_permission_catalog.py::TestRouteCoverage` fails on any route that has no gate and is not on the reviewed public allowlist.
- **Keep the legacy permission pair.** Use the same `(major, minor)` the Flask route passed to `require_permission`. Scoped API keys, including the `automation` key in `etc/saq.default.yaml` that nodes use to call each other, are granted those exact pairs, and a changed pair 403s them.
- Register in `aceapi_v2/application.py` alphabetically: `app.include_router(<x>_router, prefix="/<x>", tags=["<x>"])`.

Reference: `aceapi_v2/common/router.py`, `aceapi_v2/observable_types/router.py`.

### Service conventions

- `async def fn(session: AsyncSession, ...)`. Endpoints that only touch in-memory constants can omit the session parameter.
- **Reuse** existing services instead of duplicating queries. Example: `aceapi_v2/common/service.py:get_valid_observables` reuses `aceapi_v2/observable_types/service.py:get_observable_types` as its source of truth for the type list.

### Schema conventions

- Pydantic `BaseModel` with `ConfigDict(from_attributes=True)` for schemas backed by ORM rows. Use `Schema.model_validate(row)` to serialize.
- Lists wrapped in `ListResponse[T]` from `aceapi_v2/schemas/base.py`: `{"data": [...]}`. This leaves room for pagination metadata without breaking compatibility later.
- Do **not** replicate the legacy Flask `{"result": ...}` envelope on v2 endpoints.

### Caller updates

- **`ace_api.py` (Python client library)** — change the command string to `v2/<group>/<new_name>` so `_execute_api_call('v2/...', ...)` builds `/api/v2/<group>/<new_name>`. For list helpers, unwrap `response['data']` back into the library's existing `{'result': ...}` shape so external consumers are not broken. Example: `ace_api.py:266-274` (`get_valid_companies`).
- **Flask UI views** (`app/**/*.py`) — if a view calls legacy business logic that now lives in an async service, call it via `run_async_with_session(service_fn)` (`aceapi_v2/sync.py`). Do **not** have the view call back through the v2 HTTP endpoint. Examples: `app/analysis/views/index.py:553-554`, `app/admin/views/users.py:19`, `app/events/views/edit/modal.py:38`.
- **JavaScript / templates** — call v2 through `aceApi` (`app/static/js/ace_api.js`), which prefixes `/api/v2`, sends the session cookie, and rejects with FastAPI's own error sentence rather than its envelope. Older pages still use raw `fetch`/`$.ajax` to `/api/v2/<group>/<new_name>`. Example: `app/static/js/saq_analysis.js:695-751` (observable-comments).

### Integration routes

An integration's routes move into the integration, not into `aceapi_v2/`: a package `src/<package>/api/` with `router.py` and `service.py` (and `schemas.py` if it needs a model of its own), whose router the package registers on import with `register_integration_router("<name>", router)` (`aceapi_v2/integrations.py`, documented in `docs/INTEGRATIONS.md`). It is served under `/api/v2/integrations/<name>`, so it cannot collide with a core route.

- **The blueprint stays** when it serves templates, static files or pages; only its data routes go. Drop the `import ...app.views` from the blueprint callback and delete the module.
- **Reuse the core services.** An observable action that adds a directive and queues the alert is `request_observable_analysis()` with the integration's directive; one that only reads is `load_observable()` (both `aceapi_v2/alerts/service.py`). These give the integration the core actions' behavior: 409 on a locked alert, 422 for an observable of another type, correlation mode on a dispositioned alert.
- **Permissions.** Keep the route's legacy pair. A route that had only `@login_required` gets the pair of the closest core route (`observable:write` for an action that changes the alert or sends its content somewhere, `observable:read` for one that reads).
- **Callers** are the integration's templates: call the route through `aceApi`, as the core action templates do.
- **Tests** import the `tests/aceapi_v2/conftest.py` client fixtures into the test module; see `docs/INTEGRATIONS.md`. Give the module a name no other test module has (`test_<integration>_api.py`): some integration test directories are not packages.
- **Two repositories, two changes.** The integration's change needs a release of ACE that has `register_integration_router()`; merge it after that release, and write its PR description in its own repository.

### Auth

- `Security(get_current_auth)` accepts API key (`x-ace-auth` header), JWT bearer token, or Flask session cookie.
- `get_current_auth` (`aceapi_v2/dependencies.py`) relies on `ApiAuthResult.__bool__` (defined in `aceapi_v2/auth/schemas.py`) returning false for the empty sentinel returned by `verify_api_key` on unmatched credentials — otherwise invalid API keys would pass the dependency.

### CSRF — read this before migrating a GUI route

A GUI route migrated to v2 is called by browser JS carrying the **Flask session cookie**, which is the one credential that is *not* structurally immune to CSRF (an attacker cannot set the `Authorization` or `x-ace-auth` headers cross-site, but the browser attaches cookies for them). Since the `/admin` migration, `get_current_auth` enforces, **only in the cookie branch** and **only for unsafe methods**:

- `Sec-Fetch-Site: same-origin` or `none` → allowed; any other value → 403.
- Otherwise the `Origin` **hostname** must equal the request's hostname (`X-Forwarded-Host` honoured, because the reverse proxy forwards `Host` without a port) → else 403.
- Neither signal present → 403.

Consequences for a migration:

- Same-origin `fetch` from the GUI needs no change — browsers send `Sec-Fetch-Site` automatically. Do **not** hand-roll a CSRF token.
- Anything that proxies to the v2 app must forward `Origin`, `Sec-Fetch-Site`, `Authorization` and `x-ace-auth`. `create_api_v2_proxy()` in `saq/cli/commands/gui_api.py` (the `ace gui start` server on port 5000) forwarded only `Content-Type`/`Cookie`/`Accept` and silently broke all three; it now forwards every non-hop-by-hop header. If new writes 403 only on :5000, suspect the proxy first.
- `tests/aceapi_v2/auth/test_csrf.py` covers the matrix; extend it rather than re-deriving it.
- The destination is a JWT bearer token for GUI writes, dropping cookie auth from v2 entirely. Deferred until Flask retires.

### Tests

- Add `tests/aceapi_v2/<group>/test_router.py`. Use the `client` / `unauth_client` / `session` fixtures from `tests/aceapi_v2/conftest.py`. Mark module `pytestmark = pytest.mark.integration`.
- Cover at minimum: unauth → 401, happy path, and any filtering/validation semantics the legacy endpoint enforced.
- Run: `docker compose exec dev /venv/bin/python -m pytest tests/aceapi_v2/<group> -v`.

### Test infra — already paid

The following plumbing was set up during the `common` migration and generally does **not** need to change for subsequent groups:

- **`tests/conftest.py :: mock_api_call`** — dispatches `v2/*` ace_api commands through the FastAPI ASGI app in-process. It routes via `aceapi_v2.sync.run_async` + `httpx.AsyncClient(ASGITransport(fastapi_app))` so requests run on the same persistent background loop that the cached async SQLAlchemy engine is bound to (avoids "Future attached to a different loop").
- **`tests/saq/helpers.py :: execute_api_server`** — serves the FastAPI app at `/api/v2` through uvicorn, where nginx puts it on a node, so `ace_api` clients reach it unchanged.

If a new group adds endpoints that require new client-side support (file uploads, streaming, etc.), these fixtures may need extension.

### Gotchas

- `ace_api.py:_execute_api_call` hard-codes `/api/{command}`, so v2 URLs are passed as `v2/<path>` in the command string.
- A missing required query parameter is a FastAPI `422`, not the `400` the Flask routes returned. `ace_api` treats any non-2xx the same, so only tests that pinned the status code change.
- `_dispatch_v2`'s `iter_content` yields the whole body as one chunk, so an `ace_api` helper that streams works through it, but its chunking is not exercised there.
- A route that returns a file or a stream needs a `response_class` from `aceapi_v2/responses.py` (add one if its media type is new) and an entry in `tests/aceapi_v2/test_openapi_schema.py`, or the schema publishes it as `application/json`.
- `aceapi_v2/application.py` sets `root_path="/api/v2"` for Swagger/OpenAPI URL generation only — actual routes inside the ASGI app are at `/<group>/<name>`. `TestClient`/`AsyncClient` should request those inner paths, not `/api/v2/...`.
- `Company.json` (`saq/database/model.py:762`) and similar ORM-side `.json` properties are not needed in v2 — use Pydantic `model_validate` instead.
- If a legacy endpoint already delegates to a v2 service via `run_async_with_session` (e.g. the pre-migration `/common/get_valid_observables`), that service already exists and should be reused, not duplicated.
- **Routers registered after the app was built.** Integrations are imported during `initialize_environment()`, and importing `aceapi_v2` has built the module-level `app` before that. The app still serves them because `create_app()` includes the shared `/integrations` router once and FastAPI (0.141, pinned) resolves an included router's routes per request. `tests/aceapi_v2/test_integrations.py::TestRegistration::test_registered_after_the_app_was_built` fails if an upgrade changes that.
- **Route walks.** `app.routes` holds `_IncludedRouter` wrappers, not `APIRoute`s, so walking it for paths finds none; use `effective_route_contexts()` as `tests/saq/test_permission_catalog.py::_iter_effective_routes` does, or `app.openapi()["paths"]`.

### Deletion checklist

At the end of a migration, verify all of the following are done:

- [ ] Flask route functions deleted, and the view module once it is empty.
- [ ] Their tests under `tests/app/` refreshed or deleted.
- [ ] UI views / JS updated to call v2 endpoints or v2 services via the sync bridge.
- [ ] `tests/aceapi_v2/<group>/test_router.py` added.
- [ ] Every new route gated with the legacy `(major, minor)` pair (`tests/saq/test_permission_catalog.py` passes).
- [ ] This doc updated: status column flipped to `Migrated`, detailed table moved to the appendix, endpoint total decremented.

### Verification

```bash
# New v2 tests for the migrated group
docker compose exec dev /venv/bin/python -m pytest tests/aceapi_v2/<group> -v

# Full v2 suite (no cross-group regressions)
docker compose exec dev /venv/bin/python -m pytest -n auto tests/aceapi_v2

# Every v2 route gated, node-to-node scope still covered
docker compose exec dev /venv/bin/python -m pytest tests/saq/test_permission_catalog.py

# ace_api client integration tests (validates mock_api_call dispatch + return shapes)
docker compose exec dev /venv/bin/python -m pytest tests/test_ace_api.py -v
```

---

## Already migrated

### `/common` → `aceapi_v2/common/`

| Legacy Flask URL                         | v2 URL                                  |
|------------------------------------------|-----------------------------------------|
| `GET /common/ping`                       | `GET /api/v2/common/ping`               |
| `GET /common/get_supported_api_version`  | `GET /api/v2/common/supported_api_version` |
| `GET /common/get_valid_companies`        | `GET /api/v2/common/valid_companies`    |
| `GET /common/get_valid_observables`      | `GET /api/v2/common/valid_observables`  |
| `GET /common/get_valid_directives`       | `GET /api/v2/common/valid_directives`   |

Module: `aceapi_v2/common/{router,service,schemas}.py`. Tests: `tests/aceapi_v2/common/test_router.py`.

### `/events` → `aceapi_v2/events/`

| Legacy Flask URL                        | v2 URL                              |
|-----------------------------------------|-------------------------------------|
| `GET /events/open`                      | `GET /api/v2/events/open`           |
| `PUT /events/<id>/status`               | `PATCH /api/v2/events/{event_id}`   |
| `GET /events/export_events_to_csv` *(GUI)* | `GET /api/v2/events/export?type=csv` |

Module: `aceapi_v2/events/{router,service,schemas}.py`. Tests: `tests/aceapi_v2/events/test_router.py`.

Net-new since: `GET /api/v2/events/{event_ref}` (one event by numeric id or uuid, with its alerts' version tokens and database state). It is declared after the static `GET` routes so `/open` and `/export` are not captured by the path parameter.

**One documented exception to the "API only" framing:** `export_events_to_csv` was *not* an `aceapi/` API endpoint — it lived in the `app/events/views/` **GUI** blueprint. It was lifted onto the FastAPI side anyway because it returned a machine-readable CSV payload (`make_response(str(csv))`) rather than a rendered template; the rest of the `app/events/views/` routes (which render HTML / handle form POSTs) remain in the GUI app. Its only caller, `app/static/js/events.js`, now fetches `/api/v2/events/export?type=csv`.

Notes:
- The events endpoints reuse `Event.json` for serialization, which depends on the synchronous `get_db()` session (`Event.sorted_tags`/`tags`). Following the `aceapi_v2/alerts/service.py` precedent, the service runs sync `get_db()` helpers via `asyncio.to_thread` rather than taking an `AsyncSession`.
- `PATCH` support: `ace_api._execute_api_call` gained a `METHOD_PATCH` constant and a `json=` body parameter; the `_dispatch_v2` test shim maps `PATCH` and prefers a `json` body.
- Legacy response fidelity: `json_result` never wrapped events in a `{"result": ...}` envelope, so `ace_api.get_open_events()` unwraps the v2 `{"data": [...]}` back to a bare list and `ace_api.update_event_status()` returns the event dict directly.

### `/email` → `aceapi_v2/email/`

| Legacy Flask URL                                 | v2 URL                                         |
|--------------------------------------------------|------------------------------------------------|
| `GET /email/get_archived_email?message_id=<id>`  | `GET /api/v2/email/archive?message_id=<id>`    |

Module: `aceapi_v2/email/{router,service}.py` (no schemas: the response is the email itself, `Rfc822StreamResponse`). Tests: `tests/aceapi_v2/email/test_router.py`, plus `tests/test_ace_api.py::test_iter_archived_email` for the client round trip.

Notes:
- The Message-ID stays a query parameter: Message-IDs can contain a `/`, which a path segment would split.
- One archive lookup decides the 404 before the response starts; decryption runs as the body streams, so a decryption failure truncates the download rather than changing its status. Same as the Flask route.
- `tests/aceapi/test_engine_node_to_node.py` used the Flask email route as the endpoint the `automation` key must be denied. It probes `GET /api/v2/alerts/{uuid}` (`alert:read`), which also catches the key's scope being widened from `alert:create` to `alert:*`; the v2 email tests check that a key with the automation scope is denied.

Done in the same change, with no new endpoint: the GUI's `/download_archive` was deleted (no callers; its `md5` parameter actually carried the sha256), `close_event` was deleted and the events page now calls `PATCH /api/v2/events/{event_id}` with the configured `events.closed_status`, and `/<uuid>/event_name_candidate` was deleted together with the Add to Event dialog's event-name suggestion it served, which was not used.

### `/admin` → `aceapi_v2/users/`

The `app/auth/` user-management routes moved to `aceapi_v2/users/`; the pages that called them moved to a new permission-gated `app/admin/` blueprint. The Flask routes were deleted, not shimmed.

| Legacy Flask URL          | v2 URL                                     |
|---------------------------|--------------------------------------------|
| `GET /auth/user`          | `GET /api/v2/users/details`                |
| `POST /auth/add`          | `POST /api/v2/users/` *(201)*              |
| `POST /auth/edit`         | `PATCH /api/v2/users/`                     |
| `POST /auth/group/add`    | `POST /api/v2/users/groups` *(201)*        |
| `POST /auth/group/delete` | `POST /api/v2/users/groups/delete`         |
| `POST /auth/permission/add`    | `POST /api/v2/users/permissions`      |
| `POST /auth/permission/delete` | `POST /api/v2/users/permissions/delete` |

Plus net-new surface with no Flask ancestor: `GET /users/management-view`, `GET /users/catalog` (the permission catalog that drives the UI dropdowns), `GET`/`PATCH /users/me`, `GET /users/me/apikeys`, `GET`/`POST /users/{id}/apikeys`, `PUT`/`DELETE /users/apikeys/{key_id}`, and the preferences routes under `/users/me/preferences` (`aceapi_v2/user_preferences/`). The `/users/me` routes are gated by `require_self_service()`.

Module: `aceapi_v2/users/{router,service,schemas}.py`. Tests: `tests/aceapi_v2/users/{test_router,test_service}.py`.

Notes:
- `/auth/group/add` was a **bucket-B redirect form-handler**, previously excluded from the candidate list. It migrated anyway: the form now submits via `fetch` and the JS handles the result. A redirect handler is not permanently disqualified — it just costs a front-end change too.
- Validation moved into the service, which is the single choke point for both the GUI and the API. `create_user` had none, so blank usernames/emails produced empty user rows (`NOT NULL` is satisfied by `''`).
- A user can hold several API keys, each with its own scope, so keys are listed, edited and revoked by key id (`/users/apikeys/{key_id}`), not by user.

### `/admin/detection` → `aceapi_v2/detection/`

Net-new surface, no Flask ancestor: `GET /detection/` (paginated, filtered), `GET /detection/types`, `POST /detection/` *(201)*, `DELETE /detection/{id}` *(204)*, `PATCH /detection/{id}/expiration`. Gated on `detection:read` / `detection:write`.

Detections live in their own `observable_detections` table (`docs/OBSERVABLE_DETECTIONS.md`), not in `observables.for_detection`, so a row *is* an active detection: enabling creates one and disabling deletes it. All reads and writes go through `saq/database/util/observable_detection.py`.

Module: `aceapi_v2/detection/{router,service,schemas}.py`. Tests: `tests/aceapi_v2/detection/{test_router,test_service}.py`.

Note: `detection_context` defaults to `"manually added by {user}"` **in the router**, not the caller, so API clients get the same provenance the GUI records.

### `/intel` — deleted; alert-page detection actions → `aceapi_v2/detection/`

| Legacy Flask URL                                      | Replacement                                   |
|-------------------------------------------------------|-----------------------------------------------|
| `GET /intel/observables`                              | _(deleted, no replacement)_                   |
| `POST /intel/observables`                             | _(deleted, no replacement)_                   |
| `POST /observable_action_set_for_detection` *(GUI)*, enable  | `POST /api/v2/detection/`              |
| `POST /observable_action_set_for_detection` *(GUI)*, disable | `DELETE /api/v2/detection/{detection_id}` |
| `POST /observable_action_adjust_expiration` *(GUI)*   | `PATCH /api/v2/detection/{detection_id}/expiration` |

`/intel` had no callers but `ace_api.get_observables` / `iter_get_observables` / `set_observables`, the `get-observables` / `set-observables` subcommands built on them, and its own tests, and no requests in six months of production access logs. It was deleted with those helpers and subcommands rather than ported, so its filter set (ids, exact values, `fa_hits`, modified-by, batch id, alert/event pivots) and its batch update have no v2 form. Detections are managed one at a time through `/api/v2/detection`, from the admin page or the alert page.

The two GUI routes were deleted and the alert page's three detection actions (`app/templates/analysis/observable_actions/{enable_detection,disable_detection,adjust_expiration}.html`) call the v2 routes through `aceApi`.

Notes:
- **One permission per table.** The GUI routes were gated by `observable:write`; the v2 routes use `detection:write`, so every read and write of `observable_detections` now goes through `detection:*`. A principal holding `observable:write` without `detection:write` loses the alert-page detection actions. `observable:*` still gates comments, the interesting flag, the prevalence lookup, the observable types list and the other alert-page observable actions.
- **Disable and adjust address the detection by id.** `ObservableDetectionSummary` (the batched lookup the alert view already makes, `get_observable_detections()`) carries `detection_id` and `expires_on`, and the action templates read them from `observable_detections` in the template context. No extra query per observable.
- **Enable goes by type and value**, which the API resolves again through `resolve_detection_identity()`. The legacy route took the identity from the in-memory observable. `tests/saq/database/util/test_observable_detection.py::test_detection_from_an_alert_observable_is_found_by_the_alert_view` pins that the two land on the same row. An observable of a type no longer in the registry, or a value over `MAX_DETECTION_VALUE_LENGTH`, now gets a 400 where the legacy route stored it anyway.
- **Every matching observable gets its detection.** `get_observable_detections()` used to hand a detection to the first observable with its type and hash only. Two file observables with the same content at different paths are two observables, so the second one offered "enable" for a detection that existed. That was harmless when enable upserted; against v2, which answers 409, it was an error.
- **The adjust-expiration dialog was rebuilt** as one shared modal in `analysis/index.html` (`show_detection_expiration_modal_for()` in `saq_analysis.js`), following the observable-comment modal. The old one was rendered once per detected observable with fixed element ids, so the action opened the first observable's dialog, and its "current expiration" read a field the observable does not have and was always blank.
- **Audit lines moved to the router.** The GUI routes logged an `AUDIT:` line per enable and disable; `aceapi_v2/detection/router.py` now logs one for every create, delete and expiration change, which also covers the admin page. `service.delete_detection()` returns the removed detection (or `None`) so the line can name the value.

### `/analysis` reads — deleted; `ace_api.get_analysis` → `GET /api/v2/alerts/{uuid}`

| Legacy Flask URL                               | Replacement                                         |
|------------------------------------------------|-----------------------------------------------------|
| `GET /analysis/<uuid>`                         | `GET /api/v2/alerts/{uuid}` (already existed)       |
| `GET /analysis/resubmit/<uuid>`                | _(deleted, no replacement)_                         |
| `GET /analysis/submission/<uuid>`              | _(deleted, no replacement)_                         |
| `GET /analysis/status/<uuid>`                  | _(deleted, no replacement)_                         |
| `GET /analysis/details/<uuid>/<name>`          | _(deleted; the alert download has every details file)_ |
| `GET /analysis/file/<uuid>/<file_uuid_or_name>`| _(deleted; the alert download has every file)_      |

No new endpoint. In six months of production access logs, `resubmit`, `submission` and `details` had no requests and `status` and `file` one failed request each; their only callers in the tree were `ace_api` helpers and the CLI subcommands built on them. They were deleted with `ace_api.resubmit_alert`, `get_analysis_status`, `get_analysis_details`, `get_analysis_file`, their subcommands, and the `ace_api.Analysis.status` property, which existed only to call `/status`.

`GET /analysis/<uuid>` had a month of requests from a script (`python-requests`, through the external endpoint) that stopped a month before this change and is not in any repo. `ace_api.get_analysis` and `ace_api get-analysis` now call `GET /api/v2/alerts/{uuid}`, which answers with the same `{"result": ...}` envelope around the same tree, plus the alert's database state and version (`Alert.json`), so the helper keeps working for alerts.

Notes:
- **Alerts only.** The legacy route also served a root that had not become an alert (still in the workload, or analyzed without a detection). `GET /api/v2/alerts/{uuid}` answers 404 for those, which `ace_api.get_analysis` raises as `requests.HTTPError`.
- `aceapi/analysis.py` holds `submit` alone. Its tests read what a submission saved from storage (`RootAnalysis.load()`, encoded with the legacy `_JSONEncoder`) instead of through the deleted routes, so their assertions are unchanged; the `ace_api` client test of `Analysis.add_file` does the same.
- `tests/aceapi/test_engine_node_to_node.py::test_automation_scope_still_denies_out_of_scope_endpoints` probed `GET /api/analysis/<uuid>`. No Flask route requires `alert:read` now, so it probes `GET /api/v2/alerts/{uuid}` with the same config key, dispatched on the shared event loop like `tests/conftest.py::_dispatch_v2`.

### GUI reads → `aceapi_v2/alerts/`

| Legacy Flask URL (GUI)                       | v2 URL                                                          |
|----------------------------------------------|-----------------------------------------------------------------|
| `GET /get_alert_meta?direct=<uuid>`          | `GET /api/v2/alerts/{alert_uuid}/meta`                          |
| `GET /image?alert_uuid=&observable_uuid=`    | `GET /api/v2/alerts/{alert_uuid}/observables/{observable_uuid}/image` |
| `GET /reset_filter_alert_count`              | `GET /api/v2/alerts/count?f=...` (net-new, general)             |
| `GET /resolve_date_range?value=`             | `GET /api/v2/alerts/date-range?value=&tz=`                      |

Four read-only Tier 1 routes, all in heavy use: the alert page polls `meta` every five seconds, and the manage page's browser tab polls the count, so these two are the most-requested routes the GUI has. `/image_full` stays in Flask (it renders a page) and embeds the v2 image.

Module: `aceapi_v2/alerts/{router,service,schemas}.py`. Tests: `tests/aceapi_v2/alerts/{test_meta,test_image,test_count,test_date_range}.py`.

Notes:
- **`meta`** is `GUIAlert.get_metadata_json()`, read through the sync session in a thread without loading the alert from disk. An unknown alert is a 404 where the Flask route answered `{}`; the poll counts it as a failed check.
- **`count`** takes the same `f` share-link filters and `tz` as `GET /alerts` and counts what it lists, scoped the same way, so it closes the gap that kept this route in Flask (`AlertListPage` has no total). The tab's URL is built by `reset_filter_count_url()` (`app/analysis/views/session/filters.py`), which encodes `_default_filters()`, so the "Reset" filter is still defined once. `tests/aceapi_v2/alerts/test_count.py::test_reset_filter_count_matches_the_gui` pins that the API's count of that filter equals the GUI's own `filter_query.count_alerts()`.
- **`date-range`** returns `start` and `end` as well as the display `text` (`saq/util/relative_time.py::format_date_range`, shared with the `resolve_date_range` template filter). The Flask route read the analyst's timezone from `current_user`; the API takes `tz` like `GET /alerts`, and the relative date input carries `data-tz` for the page to pass, as the Signatures pages do. A value that does not parse is a 422, not `200 {"text": ""}`.
- **`image`** keeps the Flask route's guards: only an image file observable is served (anything else is a 404), with `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox`, and only that one observable is loaded, never the analysis tree. It streams through `ImageFileResponse` (`image/*` in the schema, the file's own type on the wire) and is `Cache-Control: private` rather than the GUI blueprint's default `public, max-age=0`. A malformed alert uuid is a 400 and an archived alert a 410, as on the other `/alerts/{alert_uuid}` routes.
- The templates that embed images (`analysis/file_observable.html`, `analysis/image_full.html`, `events/screenshots.html`) write the v2 path directly, like the alert page's download and log links.

### Manage page CSV export → `GET /api/v2/alerts/export/csv`

| Legacy Flask URL (GUI)         | v2 URL                                                        |
|--------------------------------|---------------------------------------------------------------|
| `GET /export_alerts_to_csv`    | `GET /api/v2/alerts/export/csv?f=...&tz=...` (already existed) |

No new endpoint: the manage page's Export to CSV button downloads the API's CSV export of the filters the page shows. The CSV is the API's, not the old one: UTC ISO 8601 times instead of the analyst's display timezone, usernames instead of display names, and the listing's other columns (`priority`, `company`, `location`, `archived`, `detection_count`, ...).

Notes:
- **Comments.** The old export had a Comments column and the API's did not, which is what kept this route in Flask. `GET /api/v2/alerts` rows are now `AlertListRow`: `AlertRow` plus `comments`, the comments on the alert oldest first, loaded with one more query per page (`service.load_alert_list_rows()`). The CSV joins them with a newline. The AI API's export (`aceapi_ai/export/`) extends the plain `AlertRow` and stays without them, so `ai:export` does not hand out analyst-written text; `tests/aceapi_ai/test_export.py::test_alert_comments_are_not_exported` pins that.
- **Which filters.** The view renders the URL as `data-export-url` on `#manage_filter_bar`, beside `data-effective-filters`: the effective filters (a temporary pivot included, as before) in share-link form, plus the analyst's `tz` for relative dates. The bar is what the refresh poll re-renders and the action bar is not, so the button reads the URL from the bar when clicked (`export_alerts_to_csv()` in `manage_alerts.js`) and always exports what the bar shows.
- The Flask export's regression test for an inverted Observable filter (an alert with no observables must still be exported under "NOT observable X") moved to `tests/aceapi_v2/alerts/test_list.py::TestFilters`.

### Take and Assign Ownership → `PUT /api/v2/alerts/owner`

| Legacy Flask URL (GUI)       | v2 URL                                                                  |
|------------------------------|-------------------------------------------------------------------------|
| `POST /set_owner`            | `PUT /api/v2/alerts/owner` with `owner_id` = the caller's own id        |
| `POST /assign_ownership`     | `PUT /api/v2/alerts/owner` with `owner_id` = the assignee, or `null`    |

One endpoint sets the owner of a set of alerts: the caller's own id takes them, another user's id assigns them, and `null` unassigns them. The body is `{alert_uuids, owner_id, take_owned}` (`owner_id` is required, so leaving it out cannot quietly unassign), and the answer is `{applied, skipped, message}`. Gated by `alert:write`; a caller that is not a user (a config key) gets a 400, since ownership is attributed to a user.

Why one bulk endpoint and not `PATCH /api/v2/alerts/{uuid}`, or separate take and reassign routes: the GUI changes the owner of every selected alert at once, conditionally (an alert another analyst owns is left alone unless the caller confirmed taking it from that analyst) and with a partial result, in one locked transaction; and taking, assigning and unassigning are one operation that differs only in who the new owner is. A single-alert `PATCH /api/v2/alerts/{uuid}` can be added on the same service if something needs it.

Notes:
- **One rule for every owner change.** `saq.database.util.alert.change_alert_owner()` (which replaced `take_ownership()`) runs `check_alert_ownership()` whoever the new owner is, with `new_owner_id` so an alert the new owner already has needs no confirmation.
- **Assigning asks first.** The Flask `assign_ownership` route (a bucket B form) wrote the owner with no check, so assigning silently took alerts from whoever was working them. The Assign Ownership dialog (`base.html`, set up by `setup_assign_ownership_dialog()` in `static/js/ace.js`) now shows the selection guard with the `assign` action: each other analyst whose alerts are selected gets an unticked "Reassign N alerts from X" (or "Unassign") box, the guard is drawn again when the assignee changes (`new_owner_id`), and alerts left unticked stay with their owner and are reported in the banner.
- **No Flask session.** `set_owner` flashed the "left N alerts owned by X alone" note and stored the selection in `session['checked']` for the reload to restore. The manage page now refreshes the list in place (`refresh_manage_list()`, after the confirmation dialog has closed, since the refresh skips while one is open), so the selection stays in the `$_sel` signal, and shows the note with `show_flash_message()` (`static/js/ace.js`) in `#flash_messages`, the same banner a flash gets. The alert page still reloads, and shows the note in an `alert()` first.
- `describe_skipped()` moved from `app/alert_ownership.py` to `saq/database/util/alert.py`, where the API reaches it. The per-alert `AUDIT: alert ownership taken` line gained `changed_by`, since on an assignment the new owner is not who made the change.

### Remediation dialog → `aceapi_v2/remediation/`

| Legacy Flask URL (GUI)                          | v2 URL                                                       |
|-------------------------------------------------|--------------------------------------------------------------|
| `POST /remediation_targets` (HTML table)        | `POST /api/v2/remediation/targets/lookup` (JSON)             |
| `DELETE /remediation_targets` (Remediate)       | `POST /api/v2/remediation/remediations` `{"action": "remove"}` *(201)* |
| `PUT /remediation_targets` (Restore)            | `POST /api/v2/remediation/remediations` `{"action": "restore"}` *(201)* |
| `PATCH /remediation_targets` `stop` (Stop)      | `POST /api/v2/remediation/remediations/{id}/cancel`          |
| `PATCH /remediation_targets` `delete` (Clear)   | `DELETE /api/v2/remediation/remediations/{id}` *(204)*       |

The whole mixed route moved, its HTML branch included: the lookup returns the targets of the selected alerts as JSON, each with its latest remediation, and `remediation.js` builds the table. The Flask route and `analysis/remediation_targets.html` are deleted.

Queueing creates remediation rows, so it is a POST to the collection; Stop is a state transition on one row, so it is an action subresource (the form Stripe's and GitHub's `.../cancel` take); Clear deletes the row. Stop and Clear address the row by id, the latest remediation the dialog showed, instead of "whatever is latest when the request arrives".

Notes:
- **`remediation:write`.** The writes need the new `remediation:write` (catalog entry plus the data-only migration `f26a884b17f3`); the lookup needs `remediation:read`. The Remediations page's writes moved to `remediation:write` in the same change. No grants were copied: like `engine:download`, it is a narrowing, so a principal holding only `remediation:read` becomes read-only, while `*:*` and `remediation:*` cover it.
- **Defects fixed.** Stop and Clear acted on the first selected target only (the PATCH returned inside its loop); the dialog now sends one request per target and reports what failed. Stop overwrote a completed remediation's result with `CANCELLED`; `saq.remediation.util.cancel_remediation()` stops only a remediation that is queued or in progress (a 409 otherwise) and records history only when it did.
- **One cancel rule.** The dialog's Stop has always stopped a queued (NEW) remediation, where the Remediations page's cancel stopped only IN_PROGRESS ones. The page now cancels through the same route (see the next entry).
- Queueing checks every target first (a remediator this node configures, a value its observable type accepts) and queues none on a 422. A restore still uses the restore key of the target's latest successful removal.

### Remediations and File Collections pages → `aceapi_v2/remediation/`, `aceapi_v2/file_collection/`

| Legacy Flask URL (GUI)                                                          | v2 URL                                                                  |
|---------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| `POST /remediation/remediations` (HTML list), `/remediations/page`, `/remediations/sort` | `GET /api/v2/remediation/remediations`, `/export/csv`, `/export/ndjson` |
| `GET /remediation/history/<id>` (HTML), `/history/<id>/page`                    | `GET /api/v2/remediation/remediations/{id}/history`                     |
| `PUT /remediation/remediations` (Add Remediation), `POST /remediation/mass_remediate` | `POST /api/v2/remediation/targets/lookup` `{"observables": [...]}`, then `POST /api/v2/remediation/remediations` |
| `PATCH /remediation/remediations` `cancel`                                       | `POST /api/v2/remediation/remediations/{id}/cancel`                     |
| `PATCH /remediation/remediations` `retry`                                        | `POST /api/v2/remediation/remediations/{id}/retry`                      |
| `PATCH /remediation/remediations` `restore`                                      | `POST /api/v2/remediation/remediations/{id}/restore` *(201)*            |
| `DELETE /remediation/remediations`                                               | `DELETE /api/v2/remediation/remediations/{id}` *(204)*                  |
| `POST /file_collection/collections` (HTML list), `/collections/page`, `/collections/sort` | `GET /api/v2/file-collections/`, `/export/csv`, `/export/ndjson`  |
| `GET /file_collection/history/<id>` (HTML), `/history/<id>/page`                | `GET /api/v2/file-collections/{id}/history`                             |
| `PATCH /file_collection/collections` `cancel`, `retry`                           | `POST /api/v2/file-collections/{id}/cancel`, `/{id}/retry`              |
| `DELETE /file_collection/collections`                                            | `DELETE /api/v2/file-collections/{id}` *(204)*                          |

Both pages are shells like the Signatures pages: Flask serves `GET /remediation/manage` and `GET /file_collection/manage` and nothing else. Each list is a `FilterListPage` on a new filter screen (`remediations`, `file_collections`), with filters in the URL, saved and quick filters (two defaults each), share links, CSV and NDJSON exports and keyset paging. Paging, sort and filters are no longer Flask session state. The two list APIs share `aceapi_v2/listing.py` (filters, keyset pages by id, exports). `FilterListPage` gained an opt-in checkbox column (`select`) for the selection actions, which send one request per row and report what each did.

Notes:
- **`file_collection:write`.** Stopping, retrying and deleting a request need the new `file_collection:write` (catalog entry plus the data-only migration `434f3139d204`), where `file_collection:read` used to cover them. No grants were copied, as for `remediation:write`.
- **One cancel rule.** The page's Cancel stops a queued (NEW) or IN_PROGRESS remediation, as the dialog's Stop does, and a completed one is a 409. `cancel_remediations()`, which stopped only IN_PROGRESS ones, is deleted, with the other list helpers only the page used.
- **Restore** undoes the selected removal with the restore key that removal produced, and is attributed to the analyst who asks; it used to be attributed to whoever had removed it. Only a removal that succeeded can be restored, and only a completed remediation retried (409 otherwise).
- **Add Remediation and Mass Remediation are one dialog**: a type and one value per line, then the targets found are shown before they are queued. A value its type rejects is a 422 that names it, where Mass Remediation skipped it silently.
- Column sort is gone: both lists are newest first.
- Each selection button applies to the selected rows it suits (Cancel to remediations that have not completed, and so on) and says how many it left alone.

### `/html_details` and the whitelist actions — deleted

Three `analysis` routes were deleted rather than migrated:

- **`GET /html_details`** served a field of an alert's analysis details as raw `text/html` on the GUI origin. Its only caller was `analysis/custom/ews.html`, a template nothing renders, and it had no traffic in six months. The template is deleted with it.
- **`POST /observable_action_whitelist`** and **`POST /observable_action_un_whitelist`**, the Whitelist and Un-Whitelist items of every observable's menu. Whitelisting stored a `whitelisted` tag for the observable's value, which made every later analysis containing that value stop and never alert, with no expiry and no list of what had been whitelisted. Nobody used them in six months. Suppressing observables that are not worth analyzing will be built on other work, not on these actions.

With them went the action classes and templates, the `gui.whitelist_excluded_observable_types` setting (a site config that still sets it is ignored), the `ACTION_*WHITELIST` constants, and `whitelist:write`: its catalog entry is removed by the data-only migration `e28c9d0a6154`, and existing grants are left alone since nothing checks the pair. The engine's whitelisting is unchanged: the `whitelisted` tag mappings already stored still apply through `user_defined_tagging`, and the email and YARA rules still whitelist emails. The defects listed for these routes (HTML on the GUI origin, failures reported with 200) went with them.

### File views → `GET /api/v2/alerts/{uuid}/observables/{id}/{text,hex,zip}`

| Legacy Flask URL (GUI)                                         | v2 URL                                                        |
|----------------------------------------------------------------|---------------------------------------------------------------|
| `GET /download_file?alert_uuid=&file_uuid=&mode=text` (View As Text) | `GET /api/v2/alerts/{uuid}/observables/{id}/text`       |
| `GET /download_file?...&mode=hex` (View As Hex)                | `GET /api/v2/alerts/{uuid}/observables/{id}/hex`              |
| `GET /download_file?...&mode=zip` (Download File As ZIP)       | `GET /api/v2/alerts/{uuid}/observables/{id}/zip`              |

Siblings of the `/image` route, and like it they load only the one file observable (`load_file_observable`), never the analysis tree, so this was Tier 2 in name only. The alert page's three file actions open the new URLs; the Flask route is deleted, and old `/ace/download_file` links are not redirected (they 404). The signature repository's rule comments that linked to it were rewritten in its own change.

Notes:
- **No mode serves the file as-is.** The Flask route's **Open** (`view`, `html`) and **Download File** (`raw`) modes were removed earlier because serving an alert's file inline runs a malicious HTML or JS file on the GUI origin. Don't add one. The text and hex views are `text/plain` with `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox`, so an HTML or SVG file opened in a tab stays text.
- **Hex** is formatted in Python in the format of `hexdump -C` (repeated lines squeezed to `*`), streamed in batches, where the Flask route read the whole `hexdump` output into memory first. A test compares it with the real `hexdump -C`.
- **Zip** uses `aceapi_v2/common/archive.py` (password `infected`), is deleted after it is sent, and is named after the file through `safe_file_name()` rather than the raw file name.
- All three log an `AUDIT:` line; the permission is `alert:read`, as before.

### Observable actions → `aceapi_v2/alerts/`

| Legacy Flask URL (GUI)                                            | v2 URL                                                                      |
|-------------------------------------------------------------------|-----------------------------------------------------------------------------|
| `POST /observable_action` `collect_file` (Collect File)           | `POST /api/v2/alerts/{uuid}/observables/{id}/collect-file` *(202)*          |
| `POST /observable_action` `file` (render a screenshot)            | `POST /api/v2/alerts/{uuid}/observables/{id}/render` *(202)*                |
| `POST /observable_action` `crawl` (crawl a URL)                   | `POST /api/v2/alerts/{uuid}/observables/{id}/crawl` *(202)*                 |
| `POST /observable_action_check_for_clickers`                      | `POST /api/v2/alerts/{uuid}/observables/{id}/check-for-clickers` *(202)*    |
| `POST /observable_action_open_clicker_search_splunk`              | `GET /api/v2/alerts/{uuid}/observables/{id}/clicker-searches`               |

The four writes share one helper (`_request_observable_analysis` in `aceapi_v2/alerts/service.py`): lock the alert, add the directive an analysis module waits for to the observable, and queue the alert through `request_analyst_analysis()`. They need `observable:write`, the clicker searches `observable:read`, and each logs an `AUDIT:` line. The alert page's templates call them through `request_observable_analysis()` in `saq_analysis.js`.

Notes:
- **A locked alert is a 409**, "being analyzed; try again in a moment". All four production 500s of the clicker check in six months were this: an engine worker, or the search embedding worker, held the alert's lock for a second, and the route answered 500 without logging why.
- **The 500s of `/observable_action`** (18 in six months, the last in July) were the render action passing the `GUIAlert` rather than its `RootAnalysis` to `add_workload()`, fixed in `e0542bb9` before this change.
- **Collect File works on a dispositioned alert.** It requeued the alert with `schedule()` in whatever mode it was in, and the `dispositioned` mode runs no file collection module, so on an alert an analyst had already worked it did nothing. It now goes through `request_analyst_analysis()` like the others.
- **Render adds the `render` directive.** Phishkit renders a file only when it carries that directive (or is an email attachment); the Flask action added nothing and only requeued the alert, so for most files it did nothing. Render applies to file observables; phishkit renders HTML and PDF.
- **URL crawl is back in the menu.** It was listed only in `URLObservable.jinja_available_actions` (known defect 1), so no URL observable offered it; it is now registered with `register_observable_action`, next to the clicker actions.
- **`mark_as_suspect` is gone.** No template sent it, and it did nothing.
- An observable of a type the action does not apply to is a 422. The clicker searches are an empty list when the Splunk clicker module is not configured, or has no search for the type.

### `/engine` and `/analysis/submit` → `aceapi_v2/engine/`, `aceapi_v2/analysis/`

| Legacy URL                                  | v2 URL                                             |
|---------------------------------------------|----------------------------------------------------|
| `GET /api/engine/download/<uuid>`           | `GET /api/v2/engine/download/{uuid}` (`application/x-tar`) |
| `POST /api/engine/upload/<uuid>`            | `POST /api/v2/engine/upload/{uuid}`                |
| `GET /api/engine/clear/<uuid>/<lock_uuid>`  | `POST /api/v2/engine/clear/{uuid}/{lock_uuid}`     |
| `POST /api/analysis/submit`                 | `POST /api/v2/analysis/` *(201)*                   |

The node-to-node surface, and the busiest API in ACE: in 30 days of production, about 1.7 million downloads and as many clears (nodes pulling work from each other's queues), 450,000 uploads (collectors delivering to a scanner), and about 100 submissions (New Alert, `ace hunt --submit-alerts`). Every caller goes through `ace_api.py`, whose `download`, `upload`, `clear` and `submit` now build the v2 URLs; the request bodies are unchanged (multipart: `archive` and the `upload_modifiers` JSON; `analysis` and repeated `file`), and `submit` re-wraps the v2 `{"uuid": ...}` as the library's `{"result": {"uuid": ...}}`. The legacy routes and `aceapi/analysis.py` and `aceapi/engine.py` are deleted.

Notes:
- **No fallback release.** A full replacement of a node-to-node route needs every node on the same version, and every node able to serve `/api/v2`. Every node that serves the legacy API runs `http-api-v2` beside it, and nginx proxies `/api/v2` with the same unlimited body size and 300-second timeout as `/api`. Upgrade all nodes together (drain, stop every node, start them all on the new release), so that nodes never call each other across versions; a deployment that upgrades nodes one at a time would need a release in which the client falls back to the legacy URL.
- **Capacity** is the same: 12 uvicorn workers serve `/api/v2` where 12 uwsgi processes served `/api`, and the blocking work runs in the thread pool.
- **Own container.** nginx now sends `/api/v2/engine/` to `http-api-engine` (`aceapi_v2.create_engine_app()`), so user traffic on `http-api-v2` cannot starve the engines; its worker count is set per node with `ACE_API_ENGINE_WORKERS` ([ENGINE_API.md](ENGINE_API.md)). The URLs did not change, so this needs no client change and nodes on either side of it still interoperate. `/api/v2/analysis/` stays on `http-api-v2`.
- **Permissions** are unchanged (`engine:download`, `engine:upload`, `engine:clear`, `alert:create`), so the automation key's shipped scope covers the v2 routes; `tests/aceapi_v2/engine/test_node_to_node.py` proves it with that exact scope, and `tests/saq/test_permission_catalog.py` now scans the v2 routers.
- **Clear is a POST.** It deleted a directory on a GET.
- **Errors are statuses.** An unknown work target is a 404 (was a 400), a clear with a lock that does not hold the target a 409 (was a 400), an upload over an existing directory without `overwrite` a 409, and an archive the data filter refuses (an absolute link, a link out of the directory) or that is not a tar a 400 that removes the directory it created, where the Flask upload answered a failure with a 200 carrying an error message. A submission whose observable lacks a type or value, or has an unreadable time, is a 400 that names it (was an unhandled 500), and a null `event_time` means now (was a 500).

### Saved filters → `aceapi_v2/saved_filters/` + `aceapi_v2/filter_screens/`

Six `analysis` GUI routes (`/saved_filters` create/update/delete/quick, `/saved_filter_link/<uuid>`, `/saved_filters_modal_body`) were removed. Saved filters are now per *filter screen* and go through the API: `GET`/`POST /api/v2/saved-filters/`, `GET`/`PATCH`/`DELETE /api/v2/saved-filters/{filter_uuid}`, `PUT /api/v2/saved-filters/quick-filters`, `PUT /api/v2/saved-filters/scratch/{kind}`, plus `GET /api/v2/filter-screens/{screen}` and its share-link `encode`/`decode`. The front end is a reusable component (`app/static/js/saved_filters.js`, `app/templates/saved_filters/_modals.html`) used by the alert manage page and the Signatures screens.

Notes:
- These routes use `require_screen_permission()`: the permission is the one the named screen reads its data with (`alert:read` by default), so a `signature:read` user can keep saved filters on a Signatures screen.
- Selecting a filter still ends in the Flask `select_filter` route, because the selection is session state (bucket C below). Moving data to the API does not have to move session state with it.

### `/observables/lookup` — batch prevalence lookup (net-new)

Net-new surface, no Flask ancestor: `POST /api/v2/observables/lookup` takes up to 1000 `{type, value}` pairs and returns, per pair: total non-faqueue alert count, first/last seen, a raw disposition histogram (OPEN/UNKNOWN included, so `total_alert_count == sum(disposition_counts.values())`), the newest `recent_alert_limit` alerts (uuid/disposition/insert_date), and distinct event memberships. Optional `exclude_alert_uuids` (drop the querying alert from its own counts) and `since` (bounds counts and recent alerts, deliberately not events). Gated on `observable:read`.

Results are positionally aligned with the request and carry `index`; the echoed type/value are the *normalized* forms. A bad pair gets a per-pair `error` rather than failing the batch.

Module: `aceapi_v2/observables/{router,service,schemas}.py`. Tests: `tests/aceapi_v2/observables/{test_router,test_service}.py`.

Notes:
- Identity goes through `resolve_observable_identity()` (`saq/database/util/observable_detection.py`) — the polymorphic sha256 semantics where a `file` observable's hash is `unhex(value)`, not `sha256(value)`. The same change fixed `set_observable_interesting` and observable-comment creation, which previously hashed file values naively and wrote rows the engine never matches.
- Query shape: chunked `(type, sha256)` row-constructor IN on `i_type_sha256` (500/chunk, per `saq/database/util/index.py`), one GROUP BY aggregate over `observable_mapping ⋈ alerts`, one `ROW_NUMBER()` window query for recent-N (skipped at limit 0), and one `event_mapping ⋈ events` join that never touches `alerts`. No N+1 anywhere.

### `/hunt/validate` → `aceapi_v2/hunt/`

| Legacy Flask URL      | v2 URL                        |
|-----------------------|-------------------------------|
| `POST /hunt/validate` | `POST /api/v2/hunt/validate`  |

The last route in `aceapi/`. Its caller is the separately installed `validate-hunt` CLI (`lib/signature_validator/hunt_compiler/validate.py`), which analysts install editable from a clone of this repository and a signature repository's CI clones from `main` on every run, so it moved in three steps. First the v2 route ran beside the Flask one, both calling `aceapi_v2/hunt/service.py::validate_hunt` and writing the same `HUNT_AUDIT` record. Then the CLI switched its URL, which CI picked up on its next run and analysts when they reinstalled. Once the access log showed a single user still calling the old URL, the Flask route was deleted, and with it `aceapi/`, `api_uwsgi.py`, `etc/uwsgi_api.yaml`, the `http-api` container, its nginx `/api` location and `ace api start`. A CLI installed before the switch now fails with a 404 for `/api/hunt/validate`; reinstalling it fixes that.

Module: `aceapi_v2/hunt/{router,service,schemas,audit}.py`. Tests: `tests/aceapi_v2/hunt/test_router.py`.

Notes:
- **The route answers in the CLI's shape, not FastAPI's**: 200 `{"valid": true, ...}`, 400 `{"valid": false, "error": ...}`, 415 for a body that is not JSON. The CLI reads `error` from a 400.
- **Name the stragglers instead of guessing.** Every `HUNT_AUDIT` record carries `user` and `src_ip`, and the log stream it arrives on says which container answered, so the remaining users of an old route can be listed by name. A user who has not validated since the switch does not show up either way.
- **Check what the CLI imports, not the pull.** A reinstall that runs `git pull` in the clone reports "Already up to date" against whatever remote the clone has; one analyst's clone pointed at another repository and kept installing the old CLI. `python -c 'import hunt_compiler.validate as v; print(v.__file__)'` names the file that actually runs.
- **No request timeout.** uwsgi's `harakiri` killed a worker at 300 seconds; uvicorn has none, so a validation nginx has given up on keeps its thread until the hunt's own query and correlate timeouts end it. Hunt scripts run in `http-api-v2`, beside the GUI's API traffic, which is why that container has a `pids_limit`. Hunt validation does not get a container of its own: the node-to-node routes were the traffic worth isolating, and they have `http-api-engine` ([ENGINE_API.md](ENGINE_API.md)).
- **API keys.** `aceapi/auth.py` also held the synchronous key helpers behind `ace user add-api-key`, `list-api-keys`, `revoke-api-key` and `modify --new-api-key/--clear-api-key`; they moved to `saq/database/util/user_management.py`. Requests are authenticated by `aceapi_v2/auth/`.

### Integration routes → `/api/v2/integrations/<name>`

| Legacy Flask URL (integration blueprint)                      | v2 URL                                                                                         |
|---------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| `POST /example/example_observable_action` (example integration) | `POST /api/v2/integrations/example/alerts/{alert_uuid}/observables/{observable_uuid}/example` |

New: `aceapi_v2/integrations.py` (`register_integration_router()`), included by `create_app()` under `/integrations` with the same credential check as every core router. Tests: `tests/aceapi_v2/test_integrations.py`.

The example integration (`integrations.example/`), which integration authors copy, now shows the pattern: its observable action calls `example/api/router.py` through `aceApi`, gated on `alert:read`, and its blueprint keeps only its page. The observable actions of the integrations one site runs (five routes in three integrations, every one with traffic in the last six months) moved in the same change, in their own repository.

Notes:
- **Integration actions reuse the core action services.** `aceapi_v2/alerts/service.py`'s `_request_observable_analysis` became the public `request_observable_analysis()`, and `load_observable()` was split out of `clicker_searches()`. Integration routes that went through them stopped answering a locked alert with a 500 (every 500 one of those routes answered in six months was an engine worker holding the lock) and stopped queueing a dispositioned alert in dispositioned mode, where the modules they wait for do not run.
- **Credential check at the prefix.** `create_app()` includes the `/integrations` router with `Security(get_current_auth)`, so an integration route can never be reached without a credential, whatever its router declares. The permission gate is still each route's own.

---

## Flask GUI routes (`app/`) — non-template migration candidates

The `/events` migration established the precedent that a Flask route returning a **machine-readable payload rather than a rendered template** belongs on the FastAPI side, even when it lives in an `app/` GUI blueprint. This section applies that lens to **all 82** `@blueprint.route` handlers across the ten `app/` blueprints (`app/blueprints.py::register_blueprints` imports every view module, so all of them are live). URLs below include the blueprint's `url_prefix` but not the `/ace` application root.

These GUI routes differ from the `aceapi/` API in one important way: **their callers are JavaScript and templates, not `ace_api.py`.** Migrating one means repointing a `fetch`/`$.ajax` call or a `url_for` link to `/api/v2/...`; there is no Python client to update. Auth maps cleanly: every candidate already uses `@require_permission(...)` over the Flask session cookie, which `aceapi_v2`'s `get_current_auth` accepts.

### Classification rule

- **Candidate (bucket A — API-shaped):** returns JSON (`jsonify` / `json.dumps` / dict), CSV/text data (`make_response(str(csv))`), a file/binary download (`send_from_directory` / `send_file` / streamed), or a non-template HTML/text **data** fragment.
  - **Tier 1:** touches only the database, or reads a single file observable (`load_file_observable`).
  - **Tier 2:** takes the alert lock, or loads or syncs a `RootAnalysis` from disk. Same pattern as `aceapi_v2/alerts/service.py` (sync helpers through `asyncio.to_thread`), and not a straight port.
- **Excluded — bucket B (redirect form-handlers):** POST mutates then `redirect()` + `flash()` back to a GUI page. Flask session/flash/redirect-coupled.
- **Excluded — bucket C (session view-state setters):** return 204/empty and only mutate `session['page_size'/'filters'/...]` for the GUI.
- **Excluded — `render_template`:** full pages *and* HTML fragments (modals, dynamic form rows, Datastar fragments) — all call `render_template` and stay in Flask.
- **Excluded — auth session flow:** `/login`, `/logout`, `/login/change` are Flask-Login session machinery.
- **Mixed-method handlers** (POST → `render_template` HTML fragment injected into the DOM; PUT/PATCH/DELETE → data): the **data verbs are candidates**; the **POST branch stays in Flask** (or the route must be split).

### Summary

| Blueprint         | Total | Template | Candidate (A)        | Excluded (B/C/flow) |
|-------------------|------:|---------:|---------------------:|--------------------:|
| `analysis`        |    37 |        9 |                    0 | 28 (16 B + 12 C)    |
| `events`          |    13 |        5 |                    0 |              8 (B)  |
| `remediation`     |     1 |        1 |                    0 |                   0 |
| `file_collection` |     1 |        1 |                    0 |                   0 |
| `auth`            |     3 |        0 |                    0 |           3 (flow)  |
| `admin`           |     4 |        4 |                    0 |                   0 |
| `signatures`      |     6 |        6 |                    0 |                   0 |
| `svs`             |    11 |       10 |                    0 |              1 (B)  |
| `help`            |     4 |        2 |                    0 | 2 (1 B + 1 static)  |
| `main`            |     2 |        1 |                    0 |              1 (B)  |
| **Total**         | **82**|   **39** |                **0** |              **43** |

New since the previous survey: the `svs` and `help` blueprints, and `/search/include_tests` (a session setter, C). Gone since the previous survey: `/json`, `/mark_suspect`, `/download_archive`, `/<uuid>/event_name_candidate` and `/events/close_event` (deleted rather than migrated, see the `/email` appendix entry for the last three), the six `/saved_filters*` routes (migrated, see the appendix), `/observable_action_set_for_detection` and `/observable_action_adjust_expiration` (the alert page calls `/api/v2/detection`, see the `/intel` appendix entry), `/get_alert_meta`, `/image`, `/resolve_date_range` and `/reset_filter_alert_count` (migrated, see the GUI reads appendix entry), `/export_alerts_to_csv` (the button uses the API export, see its appendix entry), `/set_owner` and `/assign_ownership` (see the alert owner appendix entry), `/remediation_targets` (see the remediation dialog appendix entry), every `remediation` and `file_collection` route but the two pages (see the Remediations and File Collections appendix entry), `/html_details`, `/observable_action_whitelist` and `/observable_action_un_whitelist` (deleted, see their appendix entry), `/download_file` (see the file views appendix entry), and `/observable_action`, `/observable_action_check_for_clickers` and `/observable_action_open_clicker_search_splunk` (see the observable actions appendix entry).

### `analysis` blueprint

37 routes total: 9 template, 16 redirect (B), 12 session (C). All files are under `app/analysis/views/`; templates under `app/templates/`, JS under `app/static/js/`.

No candidates left, in either tier; see the appendix entries for where they went.

### `events` blueprint

13 routes total: 5 template, 8 redirect (`remove_alerts`, `edit_event`, `add_tag`, and the five `bulk_*` routes). No candidates remain.

### Pages-only blueprints: `admin`, `signatures`, `svs`, `remediation`, `file_collection`, `help`, `main`, `auth`

- **`admin`** — 4 GET pages (`/admin/`, `/admin/users`, `/admin/detection`, `/admin/secrets`); all data through v2. `tests/app/admin/test_admin_smoke.py::TestAdminIsPagesOnly::test_admin_blueprint_serves_only_get_pages` enforces it.
- **`signatures`** — 6 GET pages behind a `signature:read` `before_request` gate (`app/signatures/views/access.py`); data from `/api/v2/signatures/yara-qa`, `/svs/samples`, `/svs/yara/validations`, `/filter-screens`, `/saved-filters`. `tests/app/signatures/test_signatures_smoke.py::TestSignaturesIsPagesOnly::test_signatures_blueprint_serves_only_get_pages` enforces it. The samples and validations pages write default saved filters on render (`ensure_default_saved_filters`).
- **`svs`** — 10 GET pages behind an `svs:run_read` `before_request` gate (`app/svs/views/access.py`), and `/svs/`, which redirects to the Runs tab; data from `/api/v2/svs/runs`, `/tests`, `/coverage`, `/worklist` and `/test-hosts`. `tests/app/svs/test_svs_smoke.py::TestSVSIsPagesOnly::test_svs_blueprint_serves_only_get_pages` enforces it. The list pages write default saved filters on render.
- **`remediation`**, **`file_collection`** — one GET page each (`/remediation/manage`, `remediation:read`; `/file_collection/manage`, `file_collection:read`), shells over `/api/v2/remediation` and `/api/v2/file-collections` like the Signatures pages. `tests/app/remediation/test_manage.py` and `tests/app/file_collection/test_manage.py` enforce it. Both write default saved filters on render.
- **`help`** — the training guides, for any logged-in user: 2 GET pages (`/help/`, `/help/<set>/<guide>`), `/help/<set>/`, which redirects to the set's first guide, and `/help/<set>/images/<file>`, which serves the guides' own images through `send_from_directory`. That last one is static content the pages embed, not API surface. No pages-only test; `tests/app/help/test_help_content.py` covers the content.
- **`main`** — `/` redirects (B); `/preferences` is a GET page whose saves go to `PATCH /api/v2/users/me` and `/api/v2/users/me/preferences`. No pages-only test.
- **`auth`** — `/login`, `/logout`, `/login/change`: Flask-Login session flow, stays in Flask.

This is the shape every GUI blueprint should converge on: Flask renders GET pages, the browser talks to v2. Copy the pages-only test into the next blueprint that finishes. The tests check only that a route's methods are `{GET}`, so a GET route that returns JSON still passes them.

### Cross-cutting notes for whoever migrates these

- **Callers are JS and templates, not `ace_api.py`.** Migrating a candidate = repoint its caller to `/api/v2/...` (through `aceApi` for JS) and update the response handling.
- **Mixed handlers must be split.** A POST that returns an HTML fragment for JS to inject cannot move with the data verbs of its route. The last two (`/remediation/remediations`, `/file_collection/collections`) went by turning the page into a shell that renders the list in the browser (`FilterListPage`), which is the pattern to follow.
- **Don't port the bugs.** Several candidates carry defects a straight port would preserve; see [Known defects](#known-defects-in-unmigrated-routes). Fix the behavior in the v2 version (or first, in Flask) and note it in the PR.
- **Tier 2 routes** load, lock or sync a `RootAnalysis` on disk — reuse the sync-helper-via-`asyncio.to_thread` pattern from `aceapi_v2/alerts/service.py` rather than `AsyncSession`. Treat as non-trivial.
- **Excluded buckets are intentionally omitted** from the tables above: redirect form-handlers (B), session view-state setters (C), `render_template` pages and fragments, and the auth flow. They render HTML or are Flask-session glue and are not API surface. A redirect handler is not permanently disqualified (`/auth/group/add` migrated), it just costs a front-end change too.
- **Writes are CSRF-checked.** See [CSRF](#csrf--read-this-before-migrating-a-gui-route) above. A same-origin `fetch` needs nothing extra; a proxy in front of v2 does.
- **Confirm writes persisted.** The sync bridge used to drop writes (`run_async_with_session` returned out of an `async for` mid-iteration, so `get_async_session()`'s commit never ran). Fixed, but if you are the first to migrate a *write* in some new area, check the row rather than trusting a 200.

---

## Known defects in unmigrated routes

Found while surveying the routes above. They are to be fixed separately, not as part of a migration, but a migration of one of these routes must not carry its defect over. "Verified" means reproduced against the dev instance; "code" means read from the source.

1. **Unreachable action lists** (code). The `jinja_available_actions` properties in `saq/observables/` are referenced by no template: the alert page builds its menus in the presenters (`saq/analysis/presenter/observable_presenter.py`). An action listed only there never reaches a menu; URL crawl was one, until it was registered with `register_observable_action` (see the observable actions appendix entry).
