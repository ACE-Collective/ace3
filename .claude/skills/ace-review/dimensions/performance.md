# Performance reviewer

The maintainer cares most about what the analyst feels: page loads, API latency, search. Second comes engine throughput, which decides how fast alerts appear. You look for work that scales with data size in a place where it hurts.

Read first: `CLAUDE.md` § Engineering values → Performance, and `docs/GUI_ALERT_PAGE_PERFORMANCE.md`. That doc is a case study: one alert page took 31 seconds because of N+1 queries, forks on every render and reloaded roots. If the change touches analysis modules or `saq/engine/executor.py` cache paths, also read `docs/ANALYSIS_CACHING.md`.

## Look for

**N+1 queries.**
- An ORM query or relationship access inside a loop over rows, observables or analyses.
- Lazy-loaded relationships touched per item in a template or a serializer.
- An action or permission lookup done per node of the analysis tree.
- The fix is one batched query (`IN (...)`, `selectinload`, a presenter that precomputes). `ObservablePresenter` is the model.
- Count queries where it's plausible: `tests/saq/helpers.py::count_queries` exists.

**Listing and paging.**
- A new list endpoint that pages with OFFSET or loads everything into memory. It must use keyset paging, and its exports must stream (use the shared listing helper in `aceapi_v2/common/` if there is one, otherwise follow `aceapi_v2/detection_points/`).
- A query with no index behind its filter or sort column. Check the model and migration for the index.
- An unbounded query in a request path (no limit).

**Per-request and per-render work.**
- Loading a whole `RootAnalysis` from disk to read one field.
- Forking a process (`file`, `exiftool` etc.) or opening and decoding a file on every page view.
- Recompiling regexes or YARA rules, or rebuilding config, per item.
- Derived values that should be computed once and persisted.

**Engine and analysis modules.**
- A module doing expensive work (network, subprocess, large file reads) that could be cached and isn't. Check the module's caching declarations in `saq/modules/base_module.py`.
- A cache key that misses an input, so results come back stale or wrong. That is a correctness finding; hand it to the correctness dimension by marking it `dimension: correctness`.
- Synchronous network calls on the analysis hot path with long timeouts.
- Work repeated across the observables in one root.

**Big data in memory.** Reading whole files, mailboxes or query results into memory where streaming is natural. Building huge strings or JSON blobs in a request.

**GUI.** Only rendering cost matters here: response size, the number of DOM nodes and inline scripts per node, payloads fetched repeatedly. Don't review how the JS is written.

## Calibration

- Each finding states the scale: rows or observables per request at production volume (an alert can have hundreds of observables and thousands of analyses), and the cost per item.
- A query or loop over a tiny, fixed set is not a finding.
- An N+1 on the alert page or the manage page is fix-first. One on an admin-only page that is rarely used is a nit.
