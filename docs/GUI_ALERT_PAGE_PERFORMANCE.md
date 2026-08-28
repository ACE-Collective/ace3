# Alert page performance

Why `GET /ace/analysis?direct=<uuid>` is slow on large alerts, what has been
fixed, and what is left.

## The measurement

Alert `5e8bbf6c` (an email phishing alert with phishkit detonation) took ~31
seconds of wall clock to load. Captured with `ace gui start` under
`etc/logging_configs/debug_logging.yaml`, browser against the local GUI.

| window | elapsed | what |
|---|---|---|
| `14:15:04.14` → `14:15:05.25` | ~1.1 s | `alert.load()` — parse the 1.9 MB `data.json`, rehydrate 306 observables / 1230 analyses, plus the view's batched queries and 5 external detail files |
| `14:15:05.25` → `14:15:13.68` | **~8.4 s** | Jinja render of `analysis/alert.html` |
| `14:15:13.68` → `14:15:26.37` | ~12.7 s | browser — response fully written, first stylesheet not requested for another 12.7 s |
| `14:15:26.4` → `14:15:34.4` | ~8 s | 22 `GET /ace/image` requests, each re-loading the entire `RootAnalysis` |

Shape of the alert:

- 306 unique observables (90 `file`, 22 of them images), 1230 analysis objects
- the display tree renders **450 observable nodes** and **1230 analysis nodes** — the extra 144 observable nodes are duplicate references, which still render the full observable template even though their subtree is replaced by a "Jump To Analysis" link
- only 5 of the 925 external detail files are read for a full render; analysis `details` are not rendered inline

Note that the log cannot attribute the 8.4 s render on its own: SQLAlchemy and
pymysql query logging is not emitted, and the only lines in that window are 18
`PngImagePlugin` `IHDR` entries spread evenly across it. The cost was found by
reading the render path.

## Root causes

### 1. `available_actions` re-queried per observable node — **fixed**

`ObservablePresenter.available_actions` was an uncached property, and
`app/templates/analysis/default_observable.html` reads it three times per
observable node (menu emptiness check, menu items, action sub-templates). Each
evaluation ran:

- `observable_is_set_for_detection()` — a pooled sync `SELECT`
- `observable_is_interesting()` via `run_async_with_session()` — a cross-thread
  `run_coroutine_threadsafe` hop that acquires a fresh `AsyncSession`, runs a
  one-row `SELECT`, and **commits**

450 nodes × 3 evaluations × 2 queries ≈ **2,700 round-trips per render**, half of
them full async-session-with-commit.

The view already batches both answers —
`get_all_observable_detections()` and `get_interesting_observables_by_hashes()` —
and passes them into the template for the badges. They are now also handed to the
presenters: `ObservablePresenterContext` (`app/analysis/views/index.py`) is
threaded through `TreeNode`/`_recurse`, and `ObservablePresenter.__init__` takes
`detection_status` / `is_interesting`. Presenters constructed without them (any
caller outside the alert view) still query for themselves.

`available_actions` is also memoized on the presenter. Subclasses now override
`_build_available_actions()` rather than the property, so the caching applies to
them too.

### 2. `disposition_history` re-queried per observable node — **fixed**

`Observable.disposition_history` (`saq/analysis/observable.py`) is an uncached
property that runs a 3-table `JOIN ... GROUP BY` over
`observables`/`observable_mapping`/`alerts`, and `default_observable.html` read
it twice per node → **~900 aggregate joins per render**.

`get_observable_disposition_histories()`
(`saq/database/database_observable.py`) is the batched form: one query, grouped
by `(type, sha256, disposition)` and filtered with a single indexed `IN` over the
hashes — the same shape as `get_observable_detections()`. The view builds it once
and passes `observable_disposition_history` into the template, which now reads
the dict rather than the property.

The predicate moved from `o.sha256 = UNHEX(observable.sha256_hash)` to
`o.sha256 IN (observable.sha256_bytes, ...)`. These select the same rows:
`sha256_bytes` is what `saq/database/util/index.py` writes into
`observables.sha256`, and `FileObservable._sha256_hash` is initialized from the
observable's value (the content hex) at construction, so the two agree even when
the file is no longer on disk.

Whitelisted observables are skipped, as in the per-observable form, and
observables with no history are simply absent from the dict — the template
renders nothing for either, exactly as before.

`Observable.disposition_history` is left in place for other callers.

### 3. `FileObservable.mime_type` forked `file`, and was never persisted — **fixed**

`saq/observables/file.py` shells out to `file -b --mime-type -L` and used to cache
the result only on the in-memory observable. `file_observable.html` reads
`_observable.is_image` for every file observable, so a page load forked `file`
once per file observable — 90 times for this alert. `KEY_MIME_TYPE` was already
serialized, but nothing populated it: all 90 file observables carried
`"mime_type": null` in `data.json`.

`FileTypeAnalyzer` runs the same `file --mime-type` command and now stamps the
answer onto the observable (`FileObservable.mime_type` has a setter), so it is
serialized with the alert. For alerts analyzed before this change, the getter
falls back to the observable's own `FileTypeAnalysis` details (`details['mime']`),
which have always carried the value — a small JSON read instead of a fork. The
`file` fork remains the last resort when neither is available.

`scaled_width` / `scaled_height` had the same problem — `PIL.Image.open` ran per
render (22 times here). `FileTypeAnalyzer` now calls `compute_scaled_dimensions()`
for images, and the two values are serialized alongside the mime type
(`KEY_SCALED_WIDTH` / `KEY_SCALED_HEIGHT`). Alerts serialized before those keys
existed keep the `None` from `__init__` and recompute as before.

Standalone these were cheap (90 forks = 0.32 s, 22 `Image.open` = 0.01 s, and fork
cost does not scale with process RSS), but they were pure waste.

### 4. `/ace/image` re-parsed the whole alert per request — **fixed**

`app/analysis/views/image.py` read `alert.root_analysis`, and `Alert.root_analysis`
(`saq/database/model.py`) lazily calls `self.load()` when `_root_analysis is None`
— which it always is on a freshly-queried `GUIAlert`. That was a full `data.json`
parse *and* a full analysis-tree rehydration per image, 22 times for this alert.
The endpoint only needs the file's location on disk and its mime type.

`load_file_observable(storage_dir, observable_uuid)` (`saq/analysis/root.py`)
reads the JSON and returns just that one observable, detached: it gets a file
manager, so `path` / `exists` / `mime_type` work, but no analysis tree is built.
Anything that walks analyses still has to use `load_root()`.

Measured against this alert:

| | per request |
|---|---|
| full `RootAnalysis` load + `.path` | 176.5 ms |
| `load_file_observable` + `.path` | 23.7 ms |
| …plus the `file` fork for a pre-#505 alert with no stored mime type | 28.0 ms |
| …`mime_type` when it is stored (post-#505 alert) | ~0 ms |

The remaining cost is the `json.load` of `data.json` itself (~23 ms for 1.9 MB).

Side effect: an `observable_uuid` that resolved to something other than a file
observable used to raise `AttributeError` and return a 500. It now returns the
404 the endpoint already had for a missing observable.

### 5. Response size — *open, and the largest remaining cost*

The tree is rendered fully expanded, always: the view forces
`session['prune'] = False`, and `default_collapsed` only emits
`style="display: none;"` — the subtree HTML is still generated and sent.
Each of the 450 observable nodes emits a dropdown plus an
`{% include action.action_path %}` for ~13–20 actions
(`app/templates/analysis/observable_actions/*.html`), each an inline `<script>`
block. That is the 12.7 s the browser spent before it asked for the first
stylesheet.

Fixing it means changing what the tree renders — lazily loading subtrees, or not
emitting an action sub-template per action per node. That is a GUI redesign, not
a tuning change.

## Status

| # | change | effect | state |
|---|---|---|---|
| 1 | batched detection/interesting data into `ObservablePresenter` | removes ~2,700 DB round-trips per render | **done** |
| 2 | batch `disposition_history` | removes ~900 aggregate joins per render | **done** |
| 3 | persist `mime_type` + scaled image dimensions | removes 90 `file` forks and 22 `PIL.Image.open` per render | **done** |
| 4 | `/ace/image` stops reloading the whole `RootAnalysis` | ~176 ms → ~24 ms per image request | **done** |
| 5 | reduce the rendered HTML | the ~12.7 s browser cost | not planned |

## Reproducing

```bash
ace gui start   # with etc/logging_configs/debug_logging.yaml
# then load https://localhost:5000/ace/analysis?direct=<alert uuid> in a browser
```

In `data/logs/ace-debug`, the server-side cost of the page is the gap between the
first `LOAD JSON: called load() on RootAnalysis(...)` line and the werkzeug access
line for `GET /ace/analysis?direct=...`. The baseline above was 9.5 s
(`14:15:04.143` → `14:15:13.682`).

There is no query logging in that window, so to attribute a render, count calls
rather than read the log — e.g. spy on `observable_is_set_for_detection` /
`run_async_with_session` in
`saq/analysis/presenter/observable_presenter.py`, which is what
`tests/app/analysis/views/test_index.py::test_index_does_not_query_per_observable_for_actions`
and its `..._for_disposition_history` companion do.
