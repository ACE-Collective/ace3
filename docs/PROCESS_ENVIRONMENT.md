# Process environment

What every ACE process (a service, an `ace` command, an engine worker, a GUI or API worker) can
assume about its environment once `initialize_environment()` (`saq/environment.py`) has run, and
what it must not assume before. None of this is checked when it is broken. A process that breaks
one of these rules reads the wrong file, the wrong time or the wrong setting, and usually raises
nothing.

## The working directory is `SAQ_HOME`

ACE builds most paths relative to `SAQ_HOME` and opens them relative to the cwd.
`storage_dir_from_uuid()` returns `os.path.relpath(..., start=get_base_dir())`, and
`FileObservable.full_path` joins that relative storage directory with the file's path. In any
other cwd those paths name files that do not exist, or worse, other files.

Only `ace` sets the cwd: `saq/cli/cli_main.py::main` calls `os.chdir(get_base_dir())` before
`initialize_environment()`. The uwsgi and uvicorn entry points (`ace_uwsgi.py`, `api_uvicorn.py`,
`api_engine_uvicorn.py`) never change directory and rely on the image's `WORKDIR /opt/ace`. A new
entry point that does not go through `ace` must start in `SAQ_HOME` or `chdir` there itself, and
nothing may change the cwd once ACE is running. Sandboxed tools run in the same cwd so that they
can take ACE's relative paths as they are (`docs/TOOL_SANDBOX.md`).

## Paths have different bases

Relative paths in the configuration and in a storage directory do not all resolve against the
same directory. They agree only because the cwd is `SAQ_HOME`:

| Path | Resolved against |
|---|---|
| a `config:` include in a YAML file | the cwd (`YAMLConfig.resolve_references`) |
| a path in `SAQ_CONFIG_PATHS` or `SAQ_UNITTEST_CONFIG_PATHS` | the cwd (`_load_env_config_paths`) |
| a `file:PATH` value | `SAQ_HOME` (`_read_file_value`) |
| `json_path` of a storage directory (`data.json`) | `SAQ_HOME` (`LocalFileManager.json_path`) |
| `file_dir` and `submission_json_path` of a storage directory | the cwd (`LocalFileManager`) |

A `config:` include that does not exist is skipped with an INFO record, and a missing
`SAQ_CONFIG_PATHS` file with a warning on stderr. Neither fails the load, so an include that
resolves against the wrong directory looks like a configuration with nothing in it.

## `GlobalRuntimeSettings` holds defaults until it is set

`get_global_runtime_settings()` returns a `GlobalRuntimeSettings` whose fields start as
hard-coded defaults: `/opt/ace` paths, instance type `DEV`, node `None` and the system temp
directory. `initialize_environment()` sets each field from the configuration at one line in its
body. Code that runs before that line reads the default and raises nothing.

The order matters in `initialize_environment()` itself. `initialize_encryption()` runs before
`instance_type` is set, so its check of the instance type always sees `DEV` (#1285). Code added
to `initialize_environment()`, or run from it, reads only the fields set above it. Code that needs
a configured value earlier reads it from `get_config()` instead.

## Proxy variables are removed

`initialize_environment()` deletes `http_proxy`, `https_proxy` and `ftp_proxy`, in lower and
upper case, from `os.environ`, logging a warning for each one that was set. Every child process
inherits the cleaned environment. A client that needs a proxy is given one explicitly in its own
configuration. It never inherits one from the environment.

## Everything runs on UTC

App hosts, the OS of every container and every MySQL session run on UTC. Code compares naive
datetimes from `datetime.now()` with the database's `NOW()`, and the CAS and YARA QA hold expiries
are naive local datetimes on purpose (`saq/cas/hold.py`, `saq/yara_qa/store.py`). That is only
correct while both clocks are on the same zone.

Nothing enforces it. The image sets `TZ=UTC` (`Dockerfile`), database sessions set no
`time_zone` (`saq/database/pool.py`), and `initialize_environment()` logs a warning when the
local zone is not UTC. A comparison against a stored timestamp still uses the database's
`NOW()` (AGENTS.md), which keeps it correct when an application host's clock drifts.

## Encryption is bootstrapped from the main database

Encrypted configuration values and archives are protected by one data key. Its wrapped form, with
its salt, verification hash and iteration count, is in the main database's `config` table
(`saq/crypto.py::encryption_key_set`). Two things follow:

- Every node uses the same encryption password (`SAQ_ENC`), because they all unwrap the same key.
- The main database must be reachable before any encrypted configuration value resolves.
  `initialize_encryption()` reads the `config` table, so a process that cannot reach the database
  cannot read its secrets.

The wrapped key is stored in the v0 format, which never changes (`docs/CAS.md`).

## Module-level state across a fork

The engine controller, every analysis worker and every search index worker are forked. A child
inherits every module-level client, connection and cache of its parent, and using one from two
processes corrupts it: two processes on one MySQL socket desynchronize it and both block for ever.

So every module that keeps a client, connection or singleton at module level registers a reset
with `os.register_at_fork(after_in_child=...)` where it defines the state, never at the fork site.
The hooks today are `saq/database/pool.py::_after_fork_in_child`,
`saq/storage/factory.py::reset_storage_system`, `saq/cas/registry.py::reset_cas` and
`saq/cas/metrics.py::reset`.

A hook runs inside `os.fork()`, where only the forking thread exists, so it takes no lock another
thread of the parent can hold, logs nothing and frees nothing it inherited. A reset of a singleton
is a single assignment. `_after_fork_in_child`'s docstring explains each of those rules (#982).
