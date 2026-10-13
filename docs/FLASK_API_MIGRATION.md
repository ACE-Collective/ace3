# Flask → FastAPI (`aceapi_v2/`) Migration

Playbook and progress tracker for moving Flask endpoints to the FastAPI implementation in `aceapi_v2/`. Update it in the same change as each migration.

Each `aceapi/` blueprint carries its own `url_prefix` (`aceapi/blueprints.py`) and the legacy app is served under `/api`; the FastAPI app is served under `/api/v2`.
All routes use the `@blueprint.route()` decorator pattern (no `add_url_rule()` calls).

This doc tracks two surfaces:
1. The legacy **`aceapi/` JSON API** (consumed by the `ace_api.py` client) — the original migration scope, below.
2. **`app/` GUI routes that return a machine-readable payload** (JSON / CSV / file / data) rather than a rendered template — these are *also* fair game for FastAPI, following the precedent set when `export_events_to_csv` was lifted out of the `app/events/views/` GUI blueprint during the `/events` migration. See [Flask GUI routes (`app/`) — non-template migration candidates](#flask-gui-routes-app--non-template-migration-candidates) at the end.

---

## Summary

| Blueprint  | File          | Endpoints | Methods        | Status     |
|------------|---------------|-----------|----------------|------------|
| `common`   | _(removed)_   | –         | –              | Migrated   |
| `events`   | _(removed)_   | –         | –              | Migrated   |
| `email`    | _(removed)_   | –         | –              | Migrated   |
| `analysis` | `analysis.py` | 7         | GET, POST      | Legacy     |
| `engine`   | `engine.py`   | 3         | GET, POST      | Legacy     |
| `intel`    | `intel.py`    | 2         | GET, POST      | Legacy     |
| `hunt`     | `hunt.py`     | 1         | POST           | Legacy     |

**Legacy endpoints remaining: 13** (9 GET, 4 POST).

GUI routes (`app/`): **24 API-shaped candidates** out of 94 routes (16 Tier 1, 8 Tier 2); see [the GUI section](#flask-gui-routes-app--non-template-migration-candidates).

Defects found in routes that have not migrated yet are listed under [Known defects](#known-defects-in-unmigrated-routes), for a separate fix.

### Suggested order

Cheapest and lowest-risk first. The `aceapi/` caller classes are explained under [Legacy endpoints awaiting migration](#legacy-endpoints-awaiting-migration).

1. **Detection management in one place.** `/intel/observables` GET and POST plus the GUI's `observable_action_set_for_detection` and `observable_action_adjust_expiration`, all onto `aceapi_v2/detection/`. Decide the permission pair first: the legacy routes use `observable:*`, `aceapi_v2/detection/` uses `detection:*`.
2. **`/analysis` reads** (6 routes): `ace_api` helpers only; `RootAnalysis` loads through `asyncio.to_thread`.
3. **GUI Tier 1 remainder**: `get_alert_meta`, `resolve_date_range`, `reset_filter_alert_count`, `image`, `set_owner`, `remediation_targets`, and `export_alerts_to_csv` once the v2 CSV export has the Comments column and can take the manage page's filters.
4. **`/hunt/validate`**, sequenced with a `validate-hunt` CLI release.
5. **`remediation` and `file_collection`**, after their pagination and sort leave the session.
6. **GUI Tier 2** observable actions.
7. **`/engine` and `/analysis/submit`**, last: node to node, so they need a rolling-upgrade plan.

---

## Migration playbook

A migration moves a blueprint's endpoints from Flask to FastAPI. This is a **full replacement**: the Flask routes and their module are deleted, and every caller (Python `ace_api` client, Flask-UI views, JavaScript) is updated in the same change. Do not keep Flask routes as shims.

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
- **Keep the legacy permission pair.** Use the same `(major, minor)` the Flask route passed to `api_auth_check`. Scoped API keys, including the `automation` key in `etc/saq.default.yaml` that nodes use to call each other, are granted those exact pairs, and a changed pair 403s them.
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
- **`tests/saq/helpers.py :: execute_api_server`** — serves both legacy Flask (at `/api`, wrapped with `starlette.middleware.wsgi.WSGIMiddleware`) and FastAPI (at `/api/v2`) through a single uvicorn process. `ace_api` clients continue to hit `https://host/api/...` regardless of which app ultimately handles the request.

If a new group adds endpoints that require new client-side support (file uploads, streaming, etc.), these fixtures may need extension.

### Gotchas

- `ace_api.py:_execute_api_call` hard-codes `/api/{command}`, so v2 URLs are passed as `v2/<path>` in the command string.
- A missing required query parameter is a FastAPI `422`, not the `400` the Flask routes returned. `ace_api` treats any non-2xx the same, so only tests that pinned the status code change.
- `_dispatch_v2`'s `iter_content` yields the whole body as one chunk, so an `ace_api` helper that streams works through it, but its chunking is not exercised there.
- A route that returns a file or a stream needs a `response_class` from `aceapi_v2/responses.py` (add one if its media type is new) and an entry in `tests/aceapi_v2/test_openapi_schema.py`, or the schema publishes it as `application/json`.
- `aceapi_v2/application.py` sets `root_path="/api/v2"` for Swagger/OpenAPI URL generation only — actual routes inside the ASGI app are at `/<group>/<name>`. `TestClient`/`AsyncClient` should request those inner paths, not `/api/v2/...`.
- `Company.json` (`saq/database/model.py:762`) and similar ORM-side `.json` properties are not needed in v2 — use Pydantic `model_validate` instead.
- `tests/saq/test_permission_catalog.py::TestNodeToNodeScope` derives the node-to-node permission surface by scanning `aceapi/engine.py` and names `/api/analysis/submit` explicitly. Migrating `engine` or `submit` means pointing that scan at the new router, not deleting the test: it exists because a hand-maintained list of that surface caused a production outage.
- If a legacy endpoint already delegates to a v2 service via `run_async_with_session` (e.g. the pre-migration `/common/get_valid_observables`), that service already exists and should be reused, not duplicated.

### Deletion checklist

At the end of a migration, verify all of the following are done:

- [ ] Legacy endpoint functions deleted from `aceapi/<group>.py`.
- [ ] If all endpoints in a blueprint are migrated, delete the module and remove its Blueprint + `register_blueprint(...)` lines from `aceapi/blueprints.py`.
- [ ] Legacy tests under `tests/aceapi/test_<group>*.py` refreshed or deleted.
- [ ] `ace_api.py` helpers updated to v2 URLs.
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

# Legacy Flask suite (validates run_simple → uvicorn migration + FastAPI mount)
docker compose exec dev /venv/bin/python -m pytest -n auto tests/aceapi
```

---

## Legacy endpoints awaiting migration

What decides the cost of each group is less the handler than who calls it. Three kinds of caller need different care:

- **In-process only** (`ace_api` helper, called by nothing in the tree but its tests): the cheapest. The library's external consumers see no change as long as the helper keeps its return shape.
- **Node to node** (`engine`, and `ace_api.upload`/`submit` aimed at a remote node): one ACE node calls another. During a rolling upgrade the caller can be on the new code while the node it calls is still on the old, so a v2 path that only one side has turns into a 404 for as long as the window lasts. A full replacement here needs either an all-nodes-at-once deploy or one release in which the new caller falls back to the old path.
- **Separately installed clients** (`hunt/validate` from the `validate-hunt` CLI): installed copies keep calling the old URL until they are upgraded, so the server change and the client release have to be sequenced.

### `/analysis` — `analysis.py`

| Method | URL                                          | Function         | Line | Callers |
|--------|----------------------------------------------|------------------|------|---------|
| POST   | `/analysis/submit`                           | `submit`         | 79   | `ace_api.submit` ← GUI new alert (`app/analysis/views/edit/new.py`), `ace submit`, `ace hunt`, external `ace_api` users |
| GET    | `/analysis/resubmit/<uuid>`                  | `resubmit`       | 251  | `ace_api.resubmit_alert` only |
| GET    | `/analysis/<uuid>`                           | `get_analysis`   | 265  | `ace_api.get_analysis` only |
| GET    | `/analysis/submission/<uuid>`                | `get_submission` | 280  | none — no `ace_api` helper |
| GET    | `/analysis/status/<uuid>`                    | `get_status`     | 297  | `ace_api.get_analysis_status` only |
| GET    | `/analysis/details/<uuid>/<name>`            | `get_details`    | 426  | `ace_api.get_analysis_details` only |
| GET    | `/analysis/file/<uuid>/<file_uuid_or_name>`  | `get_file`       | 444  | `ace_api.get_analysis_file` only |

The six reads load a `RootAnalysis` from disk (sync, `asyncio.to_thread`) and can be split from `submit`, which is a multipart upload with node-drain rejection (`reject_if_node_draining`) and the widest set of callers. `GET /api/v2/alerts/{alert_uuid}` overlaps `get_analysis` but is not a replacement: it serves database alerts only, while the legacy route also serves a root that is still in the workload and has no alert row. `resubmit` mutates through a `GET`; its v2 form should be a `POST`.

### `/engine` — `engine.py`

| Method | URL                                  | Function   | Line | Callers |
|--------|--------------------------------------|------------|------|---------|
| GET    | `/engine/download/<uuid>`            | `download` | 40   | `saq/engine/workload_manager/database.py` (pulling work from another node) |
| POST   | `/engine/upload/<uuid>`              | `upload`   | 84   | `saq/engine/node_manager/drain.py`, `saq/collectors/remote_node.py`, `saq/util/maintenance.py`, `saq/cli/commands/correlate.py` |
| GET    | `/engine/clear/<uuid>/<lock_uuid>`   | `clear`    | 209  | `saq/engine/workload_manager/database.py` |

Every caller is another ACE node, so this group carries the rolling-upgrade problem above. Tar streaming in both directions; `clear` mutates through a `GET`. Migrate last.

### `/intel` — `intel.py`

| Method | URL                    | Function          | Line | Callers |
|--------|------------------------|-------------------|------|---------|
| GET    | `/intel/observables`   | `get_observables` | 113  | `ace_api.get_observables` only |
| POST   | `/intel/observables`   | `set_observables` | 242  | `ace_api.set_observables` only |

Already reads and writes `observable_detections`, the same table `aceapi_v2/detection/` manages (list, create, delete, set expiration). The migration is a consolidation into that group rather than a new one: what `intel` has that `detection` lacks is the richer filter set (ids, exact/b64 values, `fa_hits`, modified-by, batch id, alert ids/uuids, event ids) and a batch update that enables, disables and edits many detections in one call.

### `/hunt` — `hunt.py`

| Method | URL              | Function        | Line | Callers |
|--------|------------------|-----------------|------|---------|
| POST   | `/hunt/validate` | `validate_hunt` | 387  | `lib/signature_validator/hunt_compiler/validate.py` (the separately installed `validate-hunt` CLI); documented in `docs/HUNTS.md` |

Compiles and executes a hunt in a request (sync, long-running, per-request log capture via `saq/logging.py`, an audit record per call). Sequencing the CLI release is the main cost; see above.

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
- `tests/aceapi/test_engine_node_to_node.py` used the Flask email route as the endpoint the `automation` key must be denied. It now probes `GET /api/analysis/<uuid>` (`alert:read`), which also catches the key's scope being widened from `alert:create` to `alert:*`; the v2 email tests check that a key with the automation scope is denied.

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

---

## Flask GUI routes (`app/`) — non-template migration candidates

The `/events` migration established the precedent that a Flask route returning a **machine-readable payload rather than a rendered template** belongs on the FastAPI side, even when it lives in an `app/` GUI blueprint. This section applies that lens to **all 94** `@blueprint.route` handlers across the eight `app/` blueprints (`app/blueprints.py::register_blueprints` imports every view module, so all of them are live). URLs below include the blueprint's `url_prefix` but not the `/ace` application root.

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
| `analysis`        |    53 |        9 | 15 (7 T1 + 8 T2)     | 29 (18 B + 11 C)    |
| `events`          |    13 |        5 |                    0 |              8 (B)  |
| `remediation`     |     7 |        2 |                    5 |                   0 |
| `file_collection` |     6 |        2 |                    4 |                   0 |
| `auth`            |     3 |        0 |                    0 |           3 (flow)  |
| `admin`           |     4 |        4 |                    0 |                   0 |
| `signatures`      |     6 |        6 |                    0 |                   0 |
| `main`            |     2 |        1 |                    0 |              1 (B)  |
| **Total**         | **94**|   **29** | **24 (16 T1 + 8 T2)**|              **41** |

Gone since the previous survey: `/json`, `/mark_suspect`, `/download_archive`, `/<uuid>/event_name_candidate` and `/events/close_event` (deleted rather than migrated, see the `/email` appendix entry for the last three) and the six `/saved_filters*` routes (migrated, see the appendix).

### `analysis` blueprint

53 routes total: 9 template, 15 candidates (7 Tier 1 + 8 Tier 2), 18 redirect (B), 11 session (C). All files are under `app/analysis/views/`; templates under `app/templates/`, JS under `app/static/js/`.

**Tier 1:**

| Method(s)          | URL                         | Function                   | file:line                 | Returns | Callers / notes |
|--------------------|-----------------------------|----------------------------|---------------------------|---------|-----------------|
| GET                | `/export_alerts_to_csv`     | `export_alerts_to_csv`     | `export.py:27`            | CSV     | `analysis/manage.html:16` (`url_for` link). Overlaps `GET /api/v2/alerts/export/csv`, which takes `f=` share-link filters rather than session state and has no Comments column; close those gaps and repoint the link. |
| GET                | `/get_alert_meta`           | `get_alert_metadata`       | `export.py:205`           | JSON    | `saq_analysis.js:86` (`check_alert_meta` poll). `GET /api/v2/alerts/{uuid}` overlaps only partly: its ETag/304 poll is cheap, but it builds the whole tree when the alert changes. |
| GET                | `/image`                    | `image`                    | `image.py:10`             | FILE    | `analysis/file_observable.html:47`, `analysis/image_full.html:2`, `events/screenshots.html:6` (`<img src>`). Serves only image types, with `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox`, because its URL can be opened as a page; keep both in v2. |
| GET                | `/resolve_date_range`       | `resolve_date_range`       | `edit/filters.py:199`     | JSON    | `manage_alerts.js:987`. Pure function. |
| GET                | `/reset_filter_alert_count` | `reset_filter_alert_count` | `manage.py:386`           | JSON    | `base.html:7` (data attribute) read by `ace.js:146`. `AlertListPage` has no total, so there is no v2 equivalent yet. |
| PUT, DELETE, PATCH | `/remediation_targets`      | `remediation_targets`      | `remediation.py:9`        | **text** | `remediation.js:8` (opened from `manage_alerts.js:358`, `saq_analysis.js:327`, `analysis/index.html:58`). **Mixed** — POST returns a template and stays. PATCH returns inside its loop, so it acts on the first target only. Every verb, writes included, is gated by `remediation:read`. |
| POST               | `/set_owner`                | `set_owner`                | `edit/ownership.py:71`    | 204     | `manage_alerts.js:55`, `saq_analysis.js:832`. Database only (`take_ownership`), but reports skipped alerts through `flash()` and sets `session['checked']`. |

**Tier 2:**

| Method(s) | URL                                             | Function                                        | file:line                                    | Returns | Callers / notes |
|-----------|-------------------------------------------------|-------------------------------------------------|----------------------------------------------|---------|-----------------|
| GET       | `/download_file`                                | `download_file`                                 | `export.py:94`                               | FILE / text | `analysis/observable_actions/{download_file_as_zip,view_as_hex,view_as_text}.html`. Modes `zip`, `hex` and `text`. There is no mode that serves the file as-is: **Open** (`view`, `html`) and **Download File** (`raw`) were removed rather than fixed, because serving an alert's file inline runs a malicious HTML or JS file on the GUI origin. Don't add one back in v2. |
| GET       | `/html_details`                                 | `html_details`                                  | `export.py:301`                              | text/html data | `analysis/custom/ews.html:4` (iframe). Serves a `details` field raw. See [Known defects](#known-defects-in-unmigrated-routes) 2. |
| POST      | `/observable_action_check_for_clickers`         | same                                            | `edit/observable_action/clicker.py:25`       | JSON    | `observable_actions/check_for_clickers.html:4`. Lock, load, delete old analysis, sync, add workload. |
| POST      | `/observable_action_open_clicker_search_splunk` | same                                            | `edit/observable_action/clicker.py:91`       | JSON    | `observable_actions/open_clicker_search_splunk.html:3`. Loads without a lock; read-only. |
| POST      | `/observable_action_set_for_detection`          | same                                            | `edit/observable_action/detection.py:17`     | text    | `observable_actions/{enable,disable}_detection.html:4`. Overlaps `POST /api/v2/detection/` and `DELETE /api/v2/detection/{id}`, but is gated by `observable:write` where v2 uses `detection:write`, addresses the observable rather than the detection id, and v2 answers 409 for an existing detection. |
| POST      | `/observable_action`                            | `observable_action`                             | `edit/observable_action/legacy.py:18`        | text    | `observable_actions/{collect_file,url_crawl,file_render}.html`. Legacy multi-action (`mark_as_suspect`, `collect_file`, `url_crawl`, `file_render`); lock, load, sync, schedule or add workload. |
| POST      | `/observable_action_whitelist`                  | same                                            | `edit/observable_action/whitelist.py:9`      | text    | `observable_actions/whitelist.html:4`. Alert load + tag-mapping write; errors come back as 200. |
| POST      | `/observable_action_un_whitelist`               | same                                            | `edit/observable_action/whitelist.py:36`     | text    | `observable_actions/un_whitelist.html:4`. Same as whitelist. |

Excluded (B) but with a v2 equivalent already: `/observable_action_adjust_expiration` (`edit/observable_action/detection.py:57`) does what `PATCH /api/v2/detection/{id}/expiration` does, and belongs with `set_for_detection` when detection management is consolidated.

### `events` blueprint

13 routes total: 5 template, 8 redirect (`remove_alerts`, `edit_event`, `add_tag`, and the five `bulk_*` routes). No candidates remain.

### `remediation` blueprint

7 routes total: 2 template (`/remediation/manage`, `/remediation/history/<id>`), 5 candidates. Front-end: `app/static/js/manage_remediations.js`. Every route, writes included, is gated by `remediation:read`; the permission catalog has no `remediation:write`, so a migration has to decide whether to add one.

| Method(s)          | URL                                              | Function            | file:line                                   | Returns | Notes |
|--------------------|--------------------------------------------------|---------------------|---------------------------------------------|---------|-------|
| PUT, PATCH, DELETE | `/remediation/remediations`                      | `remediations`      | `app/remediation/views/remediations.py:133` | JSON    | **Mixed** — POST returns a template fragment and stays. |
| GET, POST          | `/remediation/remediations/page`                 | `remediations_page` | `app/remediation/views/remediations.py:235` | JSON    | Session pagination read by the POST template branch. |
| POST               | `/remediation/remediations/sort`                 | `remediations_sort` | `app/remediation/views/remediations.py:280` | JSON    | Session sort. |
| POST               | `/remediation/mass_remediate`                    | `mass_remediate`    | `app/remediation/views/remediations.py:313` | JSON    | |
| GET, POST          | `/remediation/history/<int:remediation_id>/page` | `history_page`      | `app/remediation/views/history.py:46`       | JSON    | Session pagination read by the history template route. |

### `file_collection` blueprint

6 routes total: 2 template (`/file_collection/manage`, `/file_collection/history/<id>`), 4 candidates. Front-end: `app/static/js/manage_file_collections.js`. All gated by `file_collection:read`; no write permission exists.

| Method(s)     | URL                                                      | Function           | file:line                                      | Returns | Notes |
|---------------|----------------------------------------------------------|--------------------|------------------------------------------------|---------|-------|
| PATCH, DELETE | `/file_collection/collections`                           | `collections`      | `app/file_collection/views/collections.py:102` | JSON    | **Mixed** — POST returns a template fragment and stays. |
| GET, POST     | `/file_collection/collections/page`                      | `collections_page` | `app/file_collection/views/collections.py:214` | JSON    | Session pagination. |
| POST          | `/file_collection/collections/sort`                      | `collections_sort` | `app/file_collection/views/collections.py:259` | JSON    | Session sort. |
| GET, POST     | `/file_collection/history/<int:file_collection_id>/page` | `history_page`     | `app/file_collection/views/history.py:57`      | JSON    | Session pagination. |

The `page`, `sort` and history `page` routes in these two blueprints return JSON, but they are session view-state that the POST template branches read. Porting them means moving pagination and sort client-side (or into user preferences) first, so they are not straight ports.

### Pages-only blueprints: `admin`, `signatures`, `main`, `auth`

- **`admin`** — 4 GET pages (`/admin/`, `/admin/users`, `/admin/detection`, `/admin/secrets`); all data through v2. `tests/app/admin/test_admin_smoke.py::TestAdminIsPagesOnly::test_admin_blueprint_serves_only_get_pages` enforces it.
- **`signatures`** — 6 GET pages behind a `signature:read` `before_request` gate (`app/signatures/views/access.py`); data from `/api/v2/signatures/yara-qa`, `/svs/samples`, `/svs/yara/validations`, `/filter-screens`, `/saved-filters`. `tests/app/signatures/test_signatures_smoke.py::TestSignaturesIsPagesOnly::test_signatures_blueprint_serves_only_get_pages` enforces it. The samples and validations pages write default saved filters on render (`ensure_default_saved_filters`).
- **`main`** — `/` redirects (B); `/preferences` is a GET page whose saves go to `PATCH /api/v2/users/me` and `/api/v2/users/me/preferences`. No pages-only test.
- **`auth`** — `/login`, `/logout`, `/login/change`: Flask-Login session flow, stays in Flask.

This is the shape every GUI blueprint should converge on: Flask renders GET pages, the browser talks to v2. Copy the pages-only test into the next blueprint that finishes. Both existing tests check only that a route's methods are `{GET}`, so a GET route that returns JSON still passes them.

### Cross-cutting notes for whoever migrates these

- **Callers are JS and templates, not `ace_api.py`.** Migrating a candidate = repoint its caller to `/api/v2/...` (through `aceApi` for JS) and update the response handling.
- **Mixed handlers must be split.** The POST branch of `/remediation/remediations`, `/file_collection/collections` and `/remediation_targets` returns an HTML fragment that JS injects into the page. Only the data verbs can move; the POST stays (or gets split into a JSON endpoint + client-side rendering).
- **Don't port the bugs.** Several candidates carry defects a straight port would preserve; see [Known defects](#known-defects-in-unmigrated-routes). Fix the behavior in the v2 version (or first, in Flask) and note it in the PR.
- **Tier 2 routes** load, lock or sync a `RootAnalysis` on disk — reuse the sync-helper-via-`asyncio.to_thread` pattern from `aceapi_v2/alerts/service.py` rather than `AsyncSession`. Treat as non-trivial.
- **Excluded buckets are intentionally omitted** from the tables above: redirect form-handlers (B), session view-state setters (C), `render_template` pages and fragments, and the auth flow. They render HTML or are Flask-session glue and are not API surface. A redirect handler is not permanently disqualified (`/auth/group/add` migrated), it just costs a front-end change too.
- **Writes are CSRF-checked.** See [CSRF](#csrf--read-this-before-migrating-a-gui-route) above. A same-origin `fetch` needs nothing extra; a proxy in front of v2 does.
- **Confirm writes persisted.** The sync bridge used to drop writes (`run_async_with_session` returned out of an `async for` mid-iteration, so `get_async_session()`'s commit never ran). Fixed, but if you are the first to migrate a *write* in some new area, check the row rather than trusting a 200.

---

## Known defects in unmigrated routes

Found while surveying the routes above. They are to be fixed separately, not as part of a migration, but a migration of one of these routes must not carry its defect over. "Verified" means reproduced against the dev instance; "code" means read from the source.

1. **Unreachable action lists** (code). The `jinja_available_actions` properties in `saq/observables/` are referenced by no template: the alert page builds its menus in the presenters (`saq/analysis/presenter/observable_presenter.py`).
2. **`html_details` serves analysis details as HTML on the GUI origin** (code). It returns a field of an analysis's details raw as `text/html`, which `analysis/custom/ews.html` renders in an iframe. It also sets `response.mimtype`, a typo that leaves every response `text/html`, so its errors ("alert not found", "missing required parameter") come back as `200 text/html`, and an unknown `field` raises `KeyError` (500).
3. **`remediation_targets` PATCH acts on the first target only** (code). Its loop returns on the first iteration, so stopping or deleting the remediation of several targets at once handles one.
4. **Writes gated by read permissions** (code). Every verb of `/remediation_targets`, `/remediation/remediations` and `/remediation/mass_remediate` requires `remediation:read`, and `/file_collection/collections` PATCH and DELETE require `file_collection:read`. The permission catalog has no `remediation:write` or `file_collection:write`, so a fix adds them and decides who gets them.
5. **Whitelist actions report failure with 200** (code). `observable_action_whitelist` and `observable_action_un_whitelist` return `"operation failed: ..."` with status 200, so the page cannot tell failure from success by status.
