# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

The repo-level `../CLAUDE.md` also applies. This file covers the js_deobfuscator subsystem specifically. It is the sibling of `../phishkit/CLAUDE.md` and follows the same manager/scanner shape.

## What this is

A sandbox that runs obfuscated JavaScript and reports what it *did* rather than what it says. `harness.js` executes the sample in a `node:vm` context where every browser/Acrobat global is a recording Proxy, then emits a pseudo-JS trace of every get/set/call/construct. ACE turns that trace into a file observable and runs URL extraction over it.

Like phishkit, this directory is deliberately **external to ACE**: `js_deobfuscator.py` runs inside the manager container and must never import from the `saq` namespace. ACE talks to it only over celery.

## Two images, two roles

The naming is inverted from what you'd expect (same as phishkit):

| File | Builds | Base | Contents |
|---|---|---|---|
| `Dockerfile` | the **manager** (compose service `js-deobfuscator`, image `js-deobfuscator-manager`) | `docker:dind` | `js_deobfuscator.py` celery worker + `requirements.txt` |
| `Dockerfile.js_deobfuscator` | the **scanner** (image `js-deobfuscator`, built by the throwaway `js-deobfuscator-init` service) | `node:26-alpine` | `harness.js` + `webcrack` from `package.json` |

Both build with the **repo root as context**, so `COPY` paths are repo-relative. The manager mounts `/var/run/docker.sock` and does `docker run --rm --network none` of the scanner image per sample. `node_modules/` and `package-lock.json` are gitignored — webcrack is installed at image build time with `--ignore-scripts` (skipping isolated-vm's native build; the harness supplies a `node:vm` sandbox to webcrack instead).

## Request flow

1. `saq/modules/file_analysis/js.py` (`JavaScriptDeobfuscationAnalyzer`) fires on any `F_FILE` carrying the `type=script.javascript` yara-meta directive **or** a `.js` filename, skipping its own `deobfuscated-` output.
2. `saq/js_deobfuscator.py` `deobfuscate_file` copies the file into the shared `ace-js-deobfuscator` volume (`/js-deobfuscator/input/<uuid>/`) and calls the celery task. Scans take seconds, so the ACE side is **synchronous** — no `delay_analysis` dance (the async helpers exist but are unused). If a `<file>.dom.json` sidecar sits beside the source it is copied in alongside it (see the DOM snapshot invariant); the celery signature is unchanged, the harness discovers the sidecar by the `INPUT_PATH + '.dom.json'` convention.
3. `js_deobfuscator.py` `deobfuscate` → `_run_scanner` → `docker run` of the scanner with the input path and `/js-deobfuscator/output/<job_id>/deobfuscated.js`.
4. The task returns the output dir; ACE copies its files back out, emits `deobfuscated-<name>` as a file observable with `DIRECTIVE_EXTRACT_URLS`, and tags the source `script.javascript`.

The `ace-js-deobfuscator` named volume (created with `input/`+`output/` by `docker/startup/initialize_volumes.sh`) is the only channel for payloads and results.

Both this manager and phishkit's share one rabbitmq broker, so `js_deobfuscator.py` pins its own queue/exchange/routing key. Leaving any of them on the default `celery` makes the two workers steal each other's tasks and raise `NotRegistered`.

## Commands

```bash
# run the harness by hand — the fastest loop, no containers involved
node harness.js /path/to/sample.js /tmp/out.js && cat /tmp/out.js

# the ACE-side tests (in the dev container, /venv) — these are the real
# regression suite for harness.js
pytest tests/saq/modules/file_analysis/test_js.py
pytest tests/saq/modules/file_analysis/test_js.py::test_jquery_ready_payload_is_fired -v

# rebuild after changing harness.js or package.json
docker compose build js-deobfuscator-init js-deobfuscator
```

There is no test suite in this directory. `tests/saq/modules/file_analysis/test_js.py` monkeypatches `deobfuscate_file` with a shim that runs `node harness.js` directly, so it covers harness behavior faithfully *except* for webcrack — webcrack ships only in the scanner image, so under the shim the static pass always reports `skipped`, and the tests stub `report.json` when they need the `applied`/`failed` branches. Add a fixture under that test's `datadir` and a test there when you change harness behavior.

**Rebuilding the scanner image is what deploys a harness change.** Nothing mixes the image id into ACE's analysis cache key (unlike phishkit's `extended_version`), so also expect cached ACE results to survive a harness edit.

## Output artifact contract

`saq/modules/file_analysis/js.py` reads these by basename out of the job output dir. Renaming one silently breaks ACE:

- `deobfuscated.js` — written by the harness; the trace. Becomes the `deobfuscated-<source>` observable.
- `report.json` — the harness's stdout JSON, persisted by the manager. Fields consumed by ACE: `event_count`, `secondary_script_count`, `error`, `error_type`, `webcrack_status`, `webcrack_error`, `blob_files`, `dom_snapshot`. Adding a field means adding a `KEY_*`/property pair on `JavaScriptDeobfuscationAnalysis`.
- `blob_<n>.{html,svg,js}` — side-channel payloads (see below), listed in `report.json:blob_files`.
- `std.out`, `std.err`, `exit.code` — written by the manager, surfaced in the analysis details.

## Harness invariants

These are the parts that are easy to break in a way that loses payloads silently rather than failing loudly. The long comments in `harness.js` are the authority; this is the index.

**Recorder vs. real implementation.** A `node:vm` context starts with ECMAScript intrinsics only — every host global is absent unless the harness supplies it. The test for a new global is: *if this returned a Proxy instead of a real value, would the sample still reach its payload?* No → real implementation (`atob`, `btoa`, `TextDecoder`, `TextEncoder`, `$`/`jQuery`); yes → recorder (`document`, `fetch`, `Blob`, `URL`, the Acrobat objects). Do **not** reflexively add a name to the recorder list to fix a `ReferenceError`: for a data transform, a recorder is strictly worse than the crash — `eval(Proxy)` is a silent no-op with no error at all. `URL` staying a recorder is deliberate and the comment explains why real `URL` is worse.

**Nothing fires on its own.** There is no event loop and no DOM, so the harness drives everything by hand: `setTimeout`/`setImmediate` run their callback immediately, `setInterval` runs it 10 times, DOM-ready and jQuery `.ready()` handlers are queued and drained *after* the main script (ordering matters — samples register before defining), then 20 `setImmediate` passes drain post-`await` continuations, then string `setTimeout` bodies re-run in the same context. `process.on('unhandledRejection')` exists to stop Node exiting non-zero *after* a good trace is already written.

**Recorders memoize.** Each recorder keeps `stored` (values the sample assigned) and `children` (sub-recorders), both `Object.create(null)`. Dropping this makes every read return a fresh Proxy, so values the sample wrote to itself vanish and stringify as `[window.abcd]` inside otherwise-real URLs.

**Compile vs. runtime errors are distinguished on purpose.** `new vm.Script(...)` and `.runInContext(...)` are separate steps so `error_type` can be `compile` (SyntaxError → not JavaScript) or `runtime` (parsed, died mid-execution → definitely JavaScript). ACE only tags the source `script.javascript` in the second case. Collapsing them into `vm.runInContext` throws that signal away.

**The webcrack tail is conditional.** The post-webcrack source is appended to the trace only when `webcrack_status === 'applied'` (>2% compacted-length delta). On `skipped`/`cosmetic only`/`failed` the tail is just the raw obfuscated blob, which adds nothing and poisons downstream extractors — urlfinderlib feeds the file to an lxml HTML parser that chokes on huge string literals.

**Blob side-channel.** Text-MIME `new Blob([...])` payloads are written as sibling files so ACE's extraction pipeline can recurse into them (`html_js_extraction` → another deob pass). The extension is load-bearing; ACE names them `<source>.blob_<n>.<ext>` so the extension gates downstream still match. Bounded at `MAX_BLOB_FILES`/`MAX_BLOB_BYTES`. Add new side effects via the `constructHooks`/`callHooks` tables rather than editing `recorder()`.

**DOM snapshot.** For scripts extracted from HTML/SVG, `html_js_extraction` ships a `<script>.dom.json` sidecar the harness reads at `INPUT_PATH + '.dom.json'`. It backs `document.getElementById`/`querySelector`/`getElementsBy*` and element attribute reads (`getAttribute`, `dataset`, `textContent`, `value`) with the source document's **real** values via the recorder's optional `overrides` map — the canonical case is a phish whose redirect URL is not in the script at all but split across a sibling element's `data-*` attributes, which without real values decodes to a `[label]` placeholder and is lost silently (the recorder-loss failure mode again). A miss returns a *recorder*, not `null`, so a later `.getAttribute` can't TypeError mid-trace and lose everything after it; the `=== null` branch taking the wrong path is the accepted trade. Element-registered listeners (`addEventListener`, and `on*` property assignment via the recorder's `onSet` hook) are queued into `elementListeners` and fired **after** the DOM-ready drain and again after the async-continuation drain — the dominant shape registers the click handler from inside a `DOMContentLoaded` handler. The `querySelector` subset is deliberately `#id`/`.class`/bare-tag only; anything else degrades to a recorder. Without a sidecar the harness is byte-identical to before except for the `dom_snapshot: false` report field.
