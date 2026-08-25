# Datastar in the ACE GUI

The GUI is incrementally adopting [Datastar](https://data-star.dev) to replace custom
jQuery with declarative `data-*` attributes and server-rendered HTML fragments. There is
no big-bang rewrite: pages migrate one region at a time, and jQuery keeps working
everywhere it has not been replaced. The first page to use it is the alert management
page (`analysis/manage.html`), whose alert list auto-refreshes in place.

## The library

- Vendored as `app/static/js/datastar-<version>.js` (version in the filename, matching
  the `jquery-3.7.1.min.js` convention) and loaded once from `base.html` as an ES
  module. No CDN at runtime, no npm, no build step.
- Current version: **v1.0.2**, downloaded from
  `https://cdn.jsdelivr.net/gh/starfederation/datastar@v1.0.2/bundles/datastar.js`
  (SHA-256 `2837d87acf6ee0ba8e4e63765926c25a98d63883b02f88be194a86b81d3fd24a`).
- To upgrade: download the new bundle to a new versioned filename, update the script tag
  in `base.html`, update this file, delete the old bundle, and re-run the manual browser
  checks on every page that uses Datastar attributes.

## Syntax trap: v1 uses colons

Almost every pre-1.0 example on the internet (and in LLM training data) uses the old
dash-delimited attribute syntax. It **fails silently** in v1 — nothing happens, no
error. The v1 syntax is:

- `data-on:click`, `data-signals:foo`, `data-bind:foo`, `data-class:expanded` — colon
  between plugin name and key.
- The standalone plugins keep their hyphens: `data-on-interval`, `data-on-intersect`,
  `data-on-signal-patch`.
- `data-init` replaced `data-on-load`.

Because a wrong attribute is a silent no-op, every new Datastar attribute must be
verified in an actual browser, not just by reading the template.

## How the alert management page works (the pattern to copy)

**Server-driven fat-morph fragments.** The refreshable regions of the page are Jinja
partials whose top-level element carries a stable `id`
(`analysis/_manage_filter_bar.html` → `#manage_filter_bar`,
`analysis/_manage_alert_table.html` → `#manage_alert_table`). The full page includes
them; a refresh endpoint (`analysis.manage_refresh`) re-renders both via a shared
context-builder function and returns them as one plain `text/html` response
(`analysis/_manage_refresh.html`). Datastar matches each top-level element in the
response by `id` and morphs it into the open page, preserving id-matched nodes (their
event listeners, focus, and DOM properties survive).

No SSE and no `datastar-py` dependency are needed for this — plain HTML responses are a
fully supported patch format. The Python SDK / SSE earn adoption only if a page ever
needs multi-event responses or server push, and long-lived SSE streams would pin sync
uwsgi workers, so polling is the transport for now — see "The SSE + CQRS migration
path" below for how that changes.

**Refresh endpoint conventions** (see `manage_refresh()` in
`app/analysis/views/manage.py`):

- Same permission decorator as the page it refreshes.
- `@reject_unauthenticated_datastar` (from `app/auth/permissions.py`) above the
  permission decorator, so an expired session gets a 401 instead of a login-page
  redirect that `fetch()` would follow and Datastar would try to morph in.
- `Cache-Control: private, no-store` — per-user data must not be handed out by the
  analysis blueprint's default public cache policy.
- Never write to the session from a polled endpoint: a poll response's `Set-Cookie`
  can race a user-initiated request and clobber its session changes.
- Responses are gzip-compressed by nginx (enabled in `etc/nginx/conf.d/`) — repetitive
  fragment HTML compresses at roughly 9:1, so favor clarity over byte-shaving in the
  fragment markup.

**Signals for client-only UI state.** State that must survive a morph lives in signals,
not the DOM: checkbox selection is the `$_sel` array signal (each row checkbox has
`data-bind:_sel` with `value="<uuid>"`, so Datastar re-applies the checked property
after every morph), and expanded comment blocks are `$_openComments`. Conventions:

- Prefix client-only signals with `_` — underscore-prefixed signals are **not** sent to
  the server with `@get`/`@post` requests.
- Declare signals (`data-signals:*`) on a wrapper **outside** the morph region
  (`#manage_page`); declaring them inside would reset them to the server-rendered
  values on every refresh.
- Anything the server needs remains in the Flask session (filters, sort, pagination,
  `session['checked']`), exactly as before.

**Polling.** The non-morphed wrapper carries
`data-on-interval__duration.30s="!document.hidden && !document.querySelector('.modal.show') && @get(...)"`,
so the page refreshes only while its tab is visible and no modal is open. A
`visibilitychange` listener in `manage_alerts.js` dispatches an `ace-refresh` custom
event for an immediate catch-up when the tab is foregrounded again. The interval is
configurable via `gui.manage_auto_refresh_seconds` (0 disables). The favicon
notification-dot poll in `ace.js` follows the same setting (via the
`FAVICON_POLL_SECONDS` context processor and a `data-poll-seconds` attribute on the
favicon link), falling back to 30s when the setting is 0 — disabling the in-page
refresh must not disable the favicon indicator. Never emit `.leading`
on an interval, and never render the interval attribute inside a fragment the endpoint
returns — a morphed-in interval attribute re-arms on every poll and can storm the
server.

## Rules for code inside a morph region

- **No direct jQuery bindings** to elements inside a morph region — a recreated node
  loses them silently. Use inline attributes (`onclick=`), Datastar attributes
  (`data-on:*`), or delegated handlers (`$(document).on('click', '.selector', ...)`).
- Give a stable `id` to any element whose node identity matters across refreshes
  (checkboxes, cells that JS reads).
- Client-injected nodes that the server response does not contain **get removed by the
  morph** — `data-ignore-morph` does not save them (verified against v1.0.2: it only
  suppresses morphing an element in place, and only when both the old and new element
  carry it; it does nothing during child reconciliation). Either avoid injecting into a
  morph region, or keep the content in a registry and re-inject it from the
  `datastar-fetch` finished hook — the expanded observable rows do the latter
  (`expanded_alert_observables` in `ace.js` + `restore_alert_observables()` in
  `manage_alerts.js`). Injected content should carry `data-ignore` so Datastar does not
  process it.
- Layout-dependent initialization (measurement, widget re-init) that must re-run after
  a morph hooks the `datastar-fetch` lifecycle event —
  `init_comment_toggles()` in `manage_alerts.js` is the sanctioned example:

  ```js
  document.addEventListener("datastar-fetch", function(evt) {
      if (evt.detail && evt.detail.type === "finished") { /* re-init */ }
  });
  ```

  This is an escape hatch for things only the browser can compute; do not use it to
  rebind handlers that should be declarative or delegated.
- Never interpolate unescaped user input into a Datastar attribute — expressions are
  evaluated as JavaScript. Jinja autoescaping covers the normal cases; keep it on.

## The SSE + CQRS migration path

Datastar's ideal transport ([the Tao](https://data-star.dev/guide/the_tao_of_datastar))
is not polling but **one long-lived SSE read stream per tab**: the browser opens a
single `@get` that the server deliberately never finishes, and the server pushes
fragment patches down it the moment anything changes. Writes (disposition, ownership,
tags) stay ordinary short POSTs — that read/write split is the CQRS part, and the write
side needs no changes at all. The payoff is latency: updates appear instantly instead
of within one poll interval.

We poll today because the Flask GUI runs on synchronous uwsgi workers, where one
connection permanently occupies one worker — a handful of analysts with a few open tabs
each would exhaust the pool and take the whole GUI down with it. The migration is
therefore about **where long-lived connections are held**, not about the page pattern:
the fragments, morph-by-id, and signal conventions above all carry over unchanged, and
the client-side change is a couple of attributes (replace `data-on-interval` with
`data-init="@get('/stream')"`; Datastar reconnects automatically on drops).

**Recommended route: host the read stream on `aceapi_v2` (uvicorn).** ACE already runs
an async server; holding many idle connections cheaply is exactly what it is for, and
new endpoints belong there by repo convention anyway. Flask keeps serving everything
else. Do **not** reach for the alternative — switching Flask's workers to gevent — 
without strong reason: it changes the concurrency behavior of every GUI request at once
instead of adding one isolated endpoint.

What actually has to be built for the stream endpoint:

- **Session access.** ~~The current refresh reads the analyst's filter set from the Flask
  session cookie.~~ **Done.** Filter contents live in the `saved_filters` table; the session
  carries only UUIDs (`filter_uuid`, `filter_base_uuid`, `filter_state`,
  `filter_restore_uuid`). A stream endpoint still needs the analyst's identity, but the
  filter payload itself is already server-side.

  One consequence is worth knowing: **two tabs still share one session, and therefore one
  effective filter.** A pivot in one tab changes what the other tab's next poll renders.
  That is no longer destructive -- a pivot is a temporary filter with a labeled banner and a
  one-click Revert -- but it is not isolation. Now that every filter is addressable by UUID,
  per-tab isolation is a small follow-up (`/manage?view=<uuid>`, reading the identifier from
  the URL instead of the session) rather than the redesign it would have been while the
  payload lived in a cookie.
- **Template access.** Jinja is framework-independent — the endpoint renders the same
  `_manage_*.html` partials from the `app/templates` tree; do not fork them.
- **Change notification (the real new engineering).** Something must tell the stream
  when to push: one shared server-side watcher (polling the database once for all
  connected tabs, then fanning out) or a pub/sub channel. Client polling disappears;
  a single multiplexed watcher replaces it.
- **`datastar-py`** earns its dependency here: `SSE_HEADERS` +
  `ServerSentEventGenerator.patch_elements(...)` produce the event framing, and it
  ships a FastAPI adapter (it has no Flask adapter — another reason the stream belongs
  on `aceapi_v2`).
- **nginx.** The `/api/v2` proxy needs `proxy_buffering off` for the stream route (the
  SDK's `X-Accel-Buffering: no` header requests this, but verify). The gzip config in
  `etc/nginx/conf.d/` deliberately does not list `text/event-stream`, so streams are
  not buffered-for-compression by accident; leave it that way unless streaming
  compression is verified to flush per-event.
- **Design every event as a fat morph** — the complete current state of the fragment,
  never an incremental delta. Connections drop (laptop lids close, wifi roams); a
  reconnect that receives the next full fat morph self-heals, one that missed a delta
  does not.

Longer-term, this is also the gradual exit path from Flask: each page that migrates to
the fragment pattern turns its behavior into small self-contained endpoints, and those
are individually movable to `aceapi_v2`. Flask shrinks toward a thin shell that serves
initial page loads — retiring it eventually becomes a small step rather than a rewrite.

## Candidates for future migrations

- Bulk actions (disposition, ownership, tag, comment) patching the page in place
  instead of `window.location.replace('/ace/manage')` round trips.
- Filter / sort / pagination changes as `@get` morphs instead of full reloads.
- The favicon reset-count poll in `ace.js` as a `data-on-interval` + signal patch.
