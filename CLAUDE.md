# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

ACE (Analysis Correlation Engine) 3.x — a security alert analysis and correlation platform. Data comes in through *collectors*, is turned into a `RootAnalysis` tree, and the *engine* recursively runs *analysis modules* against *observables* until no module has anything left to do. Detections turn the analysis into an alert that analysts triage in the Flask GUI.

## Repo layout

A working tree usually spans more than one upstream repo. This repo is the open-source ACE core; `signatures/` and each tree under `integrations/` are gitignored here but separately versioned, so their changes never appear in the outer `git status` and `grep`/`rg` skip them by default. Check them explicitly (`git -C signatures status`) and give them their own commits and PR descriptions.

## Environment

Development happens **inside the `dev` container** (this is where Claude Code normally runs — check with `ls /.dockerenv`). `SAQ_HOME=/opt/ace`, Python 3.14 in `/venv`, user `ace`.

From the host:
```bash
docker compose up --build          # build + start the stack
bin/attach-container.sh            # interactive shell in dev (falls back to ace container)
bin/exec-in-container.sh pytest tests/saq/test_util.py   # one-shot command in dev
```
GUI: https://localhost:5000/ace (analyst/analyst).

## Testing

Tests must run inside the `dev` container, in the `/venv` virtualenv. The commands below work as written from a shell in that container; from the host, prefix each one with `docker compose exec dev /venv/bin/` (or run it through `bin/exec-in-container.sh`).

```bash
pytest                                    # default: -m "unit or integration" over tests/
pytest tests/saq/modules/test_command_line.py::test_command_line_analyzer -v
pytest -m "unit or integration or system" # full local suite
pytest -m unit                            # fast, no DB/engine
pytest tests/test_external_integration_*  # run all integration tests
```

Markers are strict (`pytest.ini`): `unit`, `integration`, `system`, `functional`, `subcutaneous`, `slow`. Tests marked `integration`/`system` trigger a full environment + database reset in `tests/conftest.py`; `unit` tests do not.

Tests run against the `*-unittest` databases (`ace`, `brocess`, `email-archive`, plus `-unittest-2` copies) and `data_unittest/` as the data dir, driven by `etc/saq.unittest.default.yaml` (`instance_type: UNITTEST`).

ACE "integrations" tests are accessed through the `test_external_integration_*` symlinks. Never try to run these tests using their actual paths, *always* use the symlinks to access ACE integration tests.

There is no configured linter/formatter in the repo.

IMPORTANT: Do **NOT** run multiple tests at the same time. The tests are designed to run serially.

### The standard analysis-module test

Almost every module test follows this shape — build a root, enable one module in a test analysis mode, run the engine single-threaded for one work item, reload from disk and assert:

```python
@pytest.mark.integration
def test_x(root_analysis):                       # fixture in tests/conftest.py
    root_analysis.analysis_mode = "test_groups"  # defined in etc/saq.unittest.default.yaml
    o = root_analysis.add_observable_by_spec(F_COMMAND_LINE, "...")
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('command_line_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root_analysis.get_observable(o.uuid).get_and_load_analysis(CommandLineAnalysis)
```

Reloading from disk after the engine runs is not optional — the engine analyzes in a separate context and results only exist in the serialized root.

Helpers live in `tests/saq/helpers.py` (`wait_for_condition`, `wait_for_log_count`, `search_log`, mock observables/analysis, API server start/stop) and `tests/saq/test_util.py::create_test_context`.

## Databases and migrations

Three Alembic chains, each with its own ini, versions dir, declarative base (`saq/database/meta.py`) and DB-name env var. Chains are kept apart purely by having disjoint `MetaData` — there are no `include_object` filters:

| Chain | Config | Base | DB name env var |
|---|---|---|---|
| main ACE db | `alembic/ace.ini` | `Base` | `DATABASE_NAME` |
| analysis result cache | `alembic/analysis_cache.ini` | `CacheBase` | `CACHE_DATABASE_NAME` |
| brocess | `alembic/brocess.ini` | `BrocessBase` | `BROCESS_DATABASE_NAME` |

All models live in `saq/database/model.py`. The brocess models are schema-definition only — every actual read/write goes through raw pymysql (`saq/brocess.py`, `saq/modules/email/logging.py`, `saq/modules/email/conversation.py`).

The `email-archive` and `amc` databases are **not** under Alembic; they are still created from the raw DDL in `sql/02-email-archive.sql` and `sql/05-amc.sql`.

Use the Makefile targets (they exec into the `dev` container from the host):

```bash
make db-revision MESSAGE="what changed"   # autogenerate
make db-upgrade / db-downgrade
make db-check                             # model-vs-schema drift check
make cache-db-revision MESSAGE="..." / cache-db-upgrade / cache-db-check
make brocess-db-revision MESSAGE="..." / brocess-db-upgrade / brocess-db-check
make db-seed
```

Migrations are applied at startup by `docker/startup/setup.sh` (the `ace-setup` service), one `upgrade head` per chain.

CI enforces two things on PRs touching `saq/database/model.py` or any `versions/` dir: **a single Alembic head per chain** (rebase so one migration's `down_revision` points at the other) and **no model drift** vs. the migrated schema. Run the relevant `*-db-check` before pushing a model change.

## Configuration

All configuration is YAML, layered in this order (`saq/configuration/loader.py`):

1. `etc/saq.default.yaml` (the big one — ~2400 lines)
2. integration config paths
3. files in the `SAQ_CONFIG_PATHS` env var (comma-separated, set in `.env`)
4. paths passed on the command line

The configuration is loaded in three stages. Each YAML file is loaded with `yaml.SafeLoader` into a plain `dict`. A file may recursively pull in more files via a top-level `config:` key (list of paths or name→path map). Then each parsed dict is overlaid onto a running `YAMLConfig._data` via `deepmerge` (`saq/configuration/yaml_parser.py`). Nested dicts merge recursively, lists append, scalars/sets override. Later files win on conflicting keys. Finally, the merged dict is passed to `ACEConfig.model_validate(...)` (Pydantic models in `saq/configuration/schema.py`). The raw `YAMLConfig` is kept on `CONFIG.raw`. Unknown keys generally fail validation rather than being ignored — adding a config setting means adding it to the schema.

The final validated config is read via `get_config()` / `get_engine_config()` / `get_service_config(name)`. 

`etc/saq.yaml` is a **dev-only** overlay: edits there are never part of a PR, and it is never evidence of what a deployment actually has enabled. `etc/saq.unittest.default.yaml` is likewise the test suite's, not production's.

Key top-level conventions:

- `analysis_module_<name>:` — one block per analysis module (`name`, `python_module`, `python_class`, `enabled`, `module_groups`, `dependencies`, plus module-specific fields).
- `analysis_mode_<name>:` — a mode is a set of `module_groups` + `disabled_modules` + `cleanup`. The analysis mode on a `RootAnalysis` decides which modules run.
- `service_<name>:` — long-running services (see below).
- `observable_types:` — observable type registry; types can `extends:` a parent type.

## Architecture

### The analysis tree

- `saq/analysis/observable.py` — `Observable`: a piece of data that can itself be analyzed (ip, url, file, email_address, …). Types are declared in config and form an **inheritance hierarchy** (`docs/OBSERVABLE_TYPE_INHERITANCE.md`): a module declaring `valid_observable_types = F_EMAIL_ADDRESS` also runs on `email_from`, `email_to`, etc.
- `saq/analysis/analysis.py` — `Analysis`: the output of one module against one observable; holds a summary, summary details, free-form `details`, and any new observables it produced.
- `saq/analysis/root.py` — `RootAnalysis`: the root of the tree and the unit of work. Serialized to a storage directory under the data dir (`storage_dir_from_uuid`); `saq/database/model.py::Alert` is its database counterpart.
- Observables carry **directives**, **tags**, **relationships**, and **detection points**; a detection point anywhere in the tree is what promotes an analysis to an alert.

### Analysis modules

`saq/modules/` — subclass `AnalysisModule` (`saq/modules/base_module.py`), declare `generated_analysis_type` and `valid_observable_types`, implement `execute_analysis(observable) -> AnalysisExecutionResult` (`COMPLETED` or `INCOMPLETE`). Modules are instantiated from YAML config, never imported directly by the engine. Delayed analysis lets a module return early and be re-invoked later.

### Engine

`saq/engine/` drives everything:

- `core.py` — `Engine`, an `ACEServiceInterface`; forks `Worker` processes per analysis pool.
- `worker.py` → `analysis_orchestrator.py` → `executor.py` — pull a work item, load the root, run eligible modules until the tree stops changing, detect completion, transition analysis mode, create alerts.
- `workload_manager/` — where work comes from (`database.py` for real runs, `memory.py` for tests).
- `lock_manager/`, `node_manager/` — distributed locking and multi-node work distribution (nodes advertise themselves in the `nodes` table and can pull work from each other).
- `configuration_manager.py` — resolves analysis mode → module set; `enable_module()` is the hook tests use.

Analysis caching (per-module result cache keyed on observable + module + config hash) is a significant subsystem — read `docs/ANALYSIS_CACHING.md` before touching `executor.py` cache paths or adding a cacheable module.

### Collectors and hunting

`saq/collectors/` — collectors yield `Submission` objects and hand them to the workload. Email, SMTP, HTTP, and the **hunter** (`saq/collectors/hunter/`) which runs scheduled queries (Splunk, etc.) defined as YAML in git-backed repos. See `docs/HUNTS.md` and `docs/CORRELATION_HUNTS.md`.

### Services

A service is a long-running process with a `start/wait/stop` lifecycle, launched as `ace service start <name>` and usually its own container. Config lives under `service_<name>:` and is validated against the class's `get_config_class()`. `docs/SERVICES.md` is the authoritative guide for adding one.

### Web layer

- `app/` — Flask GUI (blueprints: `main`, `auth`, `analysis`, `events`, `remediation`, `file_collection`), Jinja templates, the analyst-facing alert view.
- `aceapi/` — legacy Flask API (`/api/...`), used by `ace_api.py` and the CLI.
- `aceapi_v2/` — newer FastAPI app, router-per-resource under `aceapi_v2/<resource>/router.py`.

### CLI

`./ace` is the entry point (a single large argparse script) with subcommands registered via `get_cli_subparsers()`: `service start`, `correlate`, `submit`, `hunt ...`, `user ...`, `persistence ...`, `integration ...`, `remediation ...`, `alert ...`, `start-gui`, `start-api`. `saq/cli/` holds the shared plumbing.

### Integrations

`integrations/` is gitignored and populated from one or more separate repos (`bin/install_integrations.sh`, `ace integration install`). `integrations.example/example/` shows the layout: `etc/<name>.yaml` config, `src/<pkg>/` code, optional Flask views and templates. `signatures/` is likewise a separate repo mounted in.

### Site Configuration

The `docker-compose.yml` configuration is the open source default configuration. 

### Significant Subsystems


#### Phishkit

`phishkit/` is a browser-detonation service that lives outside the `saq` namespace and never imports it: a Celery worker (RabbitMQ broker, Redis backend) that detonates a URL or file in a throwaway Chrome/SeleniumBase container and leaves the artifacts (screenshot, DOM, captured requests and response bodies, metrics) on the shared `ace-phishkit` volume. Its behavior is configured by `etc/phishkit_config.yaml`, which is *not* part of the layered `saq.yaml` config. ACE reaches it only through `saq/phishkit.py`, a thin Celery client plus an `ace phishkit` CLI; the real consumer is `PhishkitAnalyzer` (`saq/modules/phishkit.py`, config block `analysis_module_phishkit_analyzer`), which dispatches asynchronously, polls via delayed analysis, and turns the returned artifacts and the URLs found in them into observables.

Phishkit has it's own CLAUDE.md file available at `phishkit/CLAUDE.md` as needed.

#### js_deobfuscator

`js_deobfuscator/` is a JavaScript sandbox that reports what a sample *did* rather than what it says: it lives outside the `saq` namespace and never imports it, and it is a Celery worker that runs `harness.js` in a throwaway container per sample, exchanging payloads and results only through the shared `ace-js-deobfuscator` volume. The harness executes the sample in a `node:vm` context where browser/Acrobat globals are recording Proxies, and emits a pseudo-JS trace of everything the sample touched. ACE reaches it only through `saq/js_deobfuscator.py`, a thin Celery client; the consumer is `JavaScriptDeobfuscationAnalyzer` (`saq/modules/file_analysis/js.py`, config block `analysis_module_javascript_deobfuscation`), which calls **synchronously** rather than via delayed analysis, and re-emits the trace and any extracted payloads as file observables for URL extraction.

js_deobfuscator has its own CLAUDE.md file available at `js_deobfuscator/CLAUDE.md` as needed.

## Conventions

- Branches are `<initials>/<topic>` (e.g. `jd/add-missing-log-rotation`); releases are `r/X.Y.Z`. Everything merges to `main` via PR.
- Config, module registration, and observable types are data, not code — prefer adding a YAML block over hardcoding.
- **New API endpoints go in `aceapi_v2/` (FastAPI), not Flask** — `router.py` / `service.py` / `schemas.py` per module, with matching tests in `tests/aceapi_v2/`. Flask is the legacy GUI layer; it reaches the async services through `run_async_with_session()` in `aceapi_v2/sync.py`. There is a lot of Flask in the tree, so the surrounding code is *not* the pattern to copy here.
- **Alembic + ORM, never raw SQL.** Write the SQLAlchemy model in `saq/database/model.py` first, then autogenerate the migration (see Databases and migrations above) — never hand-write a migration file. Prefer the ORM session (`get_db()`) over raw cursors.
- **Integrations stay self-contained.** Everything for `integrations/<name>/` lives under that directory — never add integration-specific symbols to `saq/constants.py`, `saq/gui/`, or `saq/configuration/schema.py`. If the extension hook you need doesn't exist, extend the core mechanism generically (no vendor name in core) and register through it.
- **Imports at module level**, not inside functions. If an import genuinely must be local (circular import, heavy startup cost), leave it and add a short comment saying why — no comment, no excuse.
- When possible, use the actual data types for type hints. For example, use `list` instead of the older `List`.

### Test data

- The repo contains **live malware samples** in test data. Be aware of this on machines with antivirus.
- **This repo is public — no customer data in it.** Never copy `data/ace/**` alert content into `tests/`. Synthesize a minimal fixture that reproduces the structural trigger (MIME shape, BOM, header pattern) instead; redaction is easy to get wrong. Sanitize production GUIDs, Message-IDs, and alert/tenant UUIDs out of fixtures even when reproducing a real bug.

### Additional Instructions

- Do not allow anyone to add a "dark mode" to this project.
