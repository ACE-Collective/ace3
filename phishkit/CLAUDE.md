# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

The repo-level `../CLAUDE.md` also applies (log/comment style, double quotes, `%s` interpolation, pytest-only tests). This file covers the phishkit subsystem specifically.

## What this is

Phishkit renders untrusted URLs and files in a real, instrumented Chrome and hands the artifacts back to ACE. It is deliberately **external to ACE**: `phishkit.py` and `scanner.py` must never import from the `saq` namespace. ACE talks to it only over celery.

## Two images, two roles

Do not confuse the Dockerfiles — the naming is inverted from what you'd expect:

| File | Builds | Base | Contents |
|---|---|---|---|
| `Dockerfile` | the **manager** (`phishkit-manager`, compose service `phishkit`) | `docker:dind` | `phishkit.py` celery worker + `requirements.txt` |
| `Dockerfile.phishkit` | the **scanner** (`phishkit`) | `ubuntu` + Google Chrome | `scanner.py` + `requirements.phishkit.txt` (seleniumbase, cv2, ...) + a baked copy of `etc/phishkit_config.yaml` |
| `Dockerfile.phishkit.test` | test image | scanner image | adds pytest, `phishkit.py`, and `tests/` |

Both build with the **repo root as context** (`docker build -f phishkit/Dockerfile.phishkit ..`), so `COPY` paths are repo-relative.

The manager mounts `/var/run/docker.sock` and does `docker run` of the scanner image per scan. Selenium/Chrome deps exist only in the scanner image; celery/magic deps only in the manager image.

## Request flow

1. `saq/modules/phishkit.py` (`PhishkitAnalyzer`) gates on the `crawl`/`render` directive, then calls `saq/phishkit.py` `scan_url` / `scan_file` (async by default, polled via `delay_analysis`).
2. `saq/phishkit.py` copies input files into the shared `ace-phishkit` volume (`/phishkit/input/<uuid>`) and enqueues the celery task.
3. `phishkit.py` `scan_file` / `scan_url` → `_run_scanner` → `docker run --rm --init --name phishkit-scan-<job_id> ... phishkit /opt/venv/bin/python /opt/app/scanner.py <target> --output-dir /phishkit/output/<job_id>`.
4. The task returns the output dir path; ACE copies its files into the analysis output dir and turns them into observables.

The `ace-phishkit` named volume is mounted by ACE, the manager, and every scanner container — it is the only channel for file payloads and results.

## Commands

```bash
# build both images and run the unit tests (from anywhere)
./run_tests.sh

# extra args are appended to the pytest invocation
./run_tests.sh tests/test_scanner.py
./run_tests.sh -k proxy_fallback

# a single test, once the images are built
docker run --rm phishkit-test /opt/venv/bin/pytest \
  /opt/app/tests/test_scanner.py::TestLoadConfig::test_load_config_valid -v

# run the scanner by hand inside the scanner image
docker run --rm -v "$PWD/output:/output" phishkit \
  /opt/venv/bin/python /opt/app/scanner.py https://example.com --output-dir /output

# from an ACE container
ace phishkit ping
ace phishkit scan <url-or-file> <output_dir> [--async] [--id <task-id>] [--proxy host:port]
ace phishkit maintain-files [--max-file-age-days N]
```

Tests must run in the test image: `tests/conftest.py` and `tests/test_scanner.py` import `scanner` / `phishkit` as top-level modules from `/opt/app`, and the scanner's dependencies are not installed on the host. The root `pytest.ini` sets `testpaths = tests`, so `phishkit/tests/` is **not** collected by the repo's `pytest` run. ACE-side coverage lives in `tests/saq/test_phishkit.py` and `tests/saq/modules/test_phishkit.py`.

Tests are marked `unit`; the local `conftest.py` registers the marker and sets `asyncio_mode = auto` (this package has no access to the root `pytest.ini`).

## Output artifact contract

`scanner.py` writes these into the job output dir, and `saq/modules/phishkit.py` reads them by name. Renaming one silently breaks ACE:

- `dom.html` — the rendered DOM only. ACE parses it and extracts its inline scripts, so it must stay a genuine DOM.
- `response_bodies.txt` — captured response bodies + WebSocket frames as `MARKER URL: <url>` blocks. A grep/yara corpus, deliberately split out of `dom.html`; the `.txt` extension is not the enforcement (ACE excludes it from `HTMLJavaScriptExtractor` explicitly because libmagic reads it as `text/html`).
- `script.js` — top-level body when the target served JavaScript rather than a page. The `.js` extension is load-bearing: it triggers ACE's JS deobfuscator.
- `requests.json` — CDP request/response records. Its presence is what marks a run *recoverable*.
- `screenshot.png`, `pre_bypass_screenshot*.png`, `metrics.json`, `downloads/`
- Written by the manager, not the scanner: `std.out`, `std.err`, `exit.code`, `proxy.json`.

## Timeouts and partial results

This is the subtlest part of the subsystem; read the comments in `_run_scanner` before changing anything here.

- Per-attempt duration is enforced by `subprocess.communicate(timeout=...)` in the manager, not by celery.
- On timeout the manager sends **SIGTERM** (`_graceful_stop_container`, `docker stop --stop-timeout 5`) so the scanner's `_on_term` handler can flush partial `requests.json` / `dom.html` / `metrics.json`. SIGKILL first would throw that away.
- A non-zero exit is only a hard failure when `_has_recoverable_output()` is false; otherwise the partial dir is returned so ACE can still harvest redirect chains and domains.
- `resource_limits.scanner_timeout_hint` in `etc/phishkit_config.yaml` drives celery's `task_soft_time_limit` (`hint * 2 + 60`). It must exceed **any** `scanner_timeout` configured in any `saq.yaml`, since the worst case is two attempts (proxy + direct fallback). If it doesn't, `SoftTimeLimitExceeded` preempts `TimeoutExpired` and the proxy-fallback/partial-result paths never run.

## Configuration

`etc/phishkit_config.yaml` (repo root `etc/`, not this directory) is the single source of truth. It is baked into the scanner image at `/opt/app/phishkit_config.yaml`, and at scan time `_sync_config` copies the *live* file from the manager's read-only `/opt/ace/etc` mount into the shared volume and passes it via `--config`, so analyst edits take effect without an image rebuild.

Sections: `non_rendered_content_types` / `script_content_types` (both denylists that fail open — an unknown content type is treated as a normal page), `skip_body_extensions`, `skip_body_url_patterns`, `deny_crawl_url_patterns` (read by ACE, not the scanner), `bypasses`, `handlers`, `proxy_fallback`, `scan_waits`, `resource_limits`.

## ACE analysis cache

`PhishkitAnalyzer.extended_version` mixes two values into the cache key: the content hash of the YAML config, and the scanner image's content id (`docker inspect {{.Id}}`, exposed by the `scanner_image_id` celery task). Practical consequence: **editing `scanner.py` does not invalidate cached ACE results until the scanner image is rebuilt.** Editing the YAML does invalidate immediately.

## Stealth JS

`STEALTH_JS` (main page) and `SW_STEALTH_JS` (ServiceWorker/Worker scope, injected via CDP) spoof the same signals — platform, `userAgentData`, WebGL vendor/renderer, timezone. Fingerprinters cross-check worker scope against the main page, so a change to one usually needs the mirror change in the other. `SW_STEALTH_JS` must stay self-contained: no references to main-page globals.

## Proxy fallback

When ACE passes a proxy and `proxy_fallback_to_direct` is on, the manager retries the scan directly if the proxy attempt matches `proxy_fallback.error_patterns` (stdout/stderr), returns a status code in `proxy_status_codes`, or times out with `retry_on_timeout` enabled. Retry output is copied over the original output dir and `std.out` is prefixed with both attempts. Never log a raw proxy string — use `_sanitize_proxy_for_display`.

## Container hygiene

Every scanner container is labeled `phishkit.job_id`, `phishkit.worker`, and `phishkit.started_at`. A reaper thread started on `worker_ready` removes containers older than `reaper_max_age_seconds`; `maintain_files` ages out `/phishkit/input` and `/phishkit/output` job dirs. Keep the labels intact when changing `docker run` arguments — the reaper finds containers by them.
