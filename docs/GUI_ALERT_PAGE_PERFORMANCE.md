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

### 2. `disposition_history` re-queried per observable node — *open*

`Observable.disposition_history` (`saq/analysis/observable.py`) is an uncached
property that runs a 3-table `JOIN ... GROUP BY` over
`observables`/`observable_mapping`/`alerts`. `default_observable.html` reads it
twice per node → **~900 aggregate joins per render**. There is no batched
equivalent yet.

### 3. `FileObservable.mime_type` forks `file`, and is never persisted — *open*

`saq/observables/file.py` shells out to `file -b --mime-type -L` and caches the
result only on the in-memory observable. `file_observable.html` reads
`_observable.is_image` for every file observable, so a page load forks `file` once
per file observable — 90 times for this alert. `KEY_MIME_TYPE` *is* serialized,
but nothing ever populates it: all 90 file observables carry `"mime_type": null`
in `data.json`. The value already exists on disk in each observable's
`FileTypeAnalysis` details as `details['mime']`.

`scaled_width` / `scaled_height` have the same problem — `PIL.Image.open` runs
per render (22 times here) and the result is never persisted.

Standalone these are cheap (90 forks = 0.32 s, 22 `Image.open` = 0.01 s, and fork
cost does not scale with process RSS), but they are pure waste.

### 4. `/ace/image` re-parses the whole alert per request — *open*

`app/analysis/views/image.py` reads `alert.root_analysis`, and
`Alert.root_analysis` (`saq/database/model.py`) lazily calls `self.load()` when
`_root_analysis is None` — which it always is on a freshly-queried `GUIAlert`.
That is a full 1.9 MB `data.json` parse per image, ~90–440 ms each, 22 times. The
endpoint only needs the file's path and mime type. It then forks `file` again for
the `Content-Type` header.

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
| 2 | batch `disposition_history` | removes ~900 aggregate joins per render | open |
| 3 | persist `mime_type` + scaled image dimensions | removes 90 `file` forks and 22 `PIL.Image.open` per render | open |
| 4 | `/ace/image` stops reloading the whole `RootAnalysis` | removes 22 × 1.9 MB `data.json` parses | open |
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
does.
