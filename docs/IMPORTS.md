# What a process imports

Every ACE process (each service, every `ace` command, every engine worker, every API worker) holds what its
modules import at module level, whether it uses it or not. Nearly all of that memory is private to the process. Even a
forked process copies most of what it inherits, because Python's reference counts and garbage collector write to the
objects. So an import added to a module that everything loads costs every process on every node.

These rules come from the October 2026 import work:
- A service that touched nothing but its own loop went from 211–228 MB to 35 MB.
- A service that uses the ORM went to 74–97 MB.
- The engine API's workers went from 194 to 96 MB.

## The rules

1. **A package `__init__.py` imports nothing.**
   - Importing any module of a package runs its `__init__.py` first. A re-export there loads the whole package into everything that imports one module from it.
   - Names stay importable from the package through a PEP 562 `__getattr__` that imports the defining module on first use. Examples: `saq/analysis/__init__.py`, `saq/gui/__init__.py`, `saq/database/__init__.py`, `saq/modules/file_analysis/__init__.py`, `saq/collectors/hunter/__init__.py`.
   - Don't export a name that is also a submodule's name. Importing the submodule rebinds the name to the module (`saq.database.retry`).
   - The `__init__.py` of `aceapi_v2/`, `aceapi_ai/` and `app/` has nothing to re-export, and imports nothing at all.
2. **Core does not import the web layer.**
   - Nothing under `saq/` imports Flask, FastAPI, `app/`, `aceapi_v2/` or `aceapi_ai/` at module level. `saq.gui.alert` uses `flask.url_for`, so only the apps import it.
   - Integrations register their API routers by module path, `register_integration_router("name", "pkg.api.router")`, which the API imports when it builds its app.
   - Integrations import Flask only under `TYPE_CHECKING`.
   - The engine API's container imports `aceapi_v2.app_factory`, never `aceapi_v2.application`, which imports every router.
3. **Initialization loads what every process needs, and nothing else.**
   - `initialize_environment()` runs in every process.
   - A subsystem only some processes use is set up on first use: the ORM engine and session (`get_db()`), the email archive's S3 backend, phishkit's celery app, the observable type hierarchy.
   - The `ace` script imports only the command module it runs (`saq/cli/commands/__init__.py`).
4. **An analysis module imports the tools its analyzer runs in the method that runs them.**
   - Loading an alert imports the module of every analysis class in it. The search indexer, the GUI and the API load alerts without running a single analyzer.
   - So a library an analyzer needs to do its work (OCR, office and PDF parsers, a network client, celery) is imported where it is used. The `Analysis` class, constants and light helpers stay at module level.
   - Examples: `saq/modules/file_analysis/ocr.py`, `saq/modules/rdap.py`.
   - An engine worker loads each library the first time it runs that analyzer.
5. **A name needed only for a type annotation is imported under `TYPE_CHECKING`.**
6. **A dependency is in `installer/requirements.txt` because ACE uses it.** Some libraries import an optional dependency whenever it is installed. pytesseract imports pandas, which cost every engine worker and GUI process 27 MB for nothing.

A local import made for rule 4, or to break a cycle, still gets its one-line comment (CLAUDE.md, Conventions).

## Enforcement

`tests/saq/test_imports.py` imports in fresh interpreters. The test process has imported nearly everything before a test runs, so an import problem is invisible from inside it. The tests check that:
- every configured service, the CLI and the apps import first, without an import cycle
- the light services load neither the API, the GUI, Flask, the observables, urlfinderlib, requests, the search client nor the analysis tools, and those without a database also leave SQLAlchemy out
- initialization, the database connections, the package inits, the URL helpers, the engine API and the search extractors each load only what they need

A new service, entry point or heavy dependency gets a line there.

## Measuring

Attributing memory to imports is order-dependent: a step pays for whatever it is the first to import. So measure like this:
- Use a fresh interpreter, after `initialize_environment()`.
- Read `RssAnon` from `/proc/self/status` before and after the import.
- Repeat in another order before believing a number.

`python -X importtime` shows the import tree and how long it takes, not its memory.

## Forked processes

The engine forks its workers. `Worker.start()` calls `gc.freeze()` right before the fork and `gc.unfreeze()` right after it, in the parent.
- The worker keeps what it inherited out of its collector's reach, so its collections don't copy every page that holds an inherited object. That's about 27 MB per worker, once a busy worker's collector would have reached them.
- The engine process unfreezes at once, so it still collects its own garbage.
- Keep the pair if you change how workers start.
