# Scheduled maintenance tasks (`etc/cron/`)

ACE's periodic maintenance runs from three directories, one per cadence, in the style of the unix
`run-parts` / `/etc/cron.daily` model:

```
etc/cron/hourly/    every hour      (bin/hourly-maintenance.sh)
etc/cron/daily/     05:00 daily     (bin/daily-maintenance.sh)
etc/cron/weekly/    05:00 Monday    (bin/weekly-maintenance.sh)
```

Each file in a directory is one logical task. The schedules themselves live in `etc/cron.yaml`
(run by the `cron` service through yacron), which calls the `bin/<cadence>-maintenance.sh` wrapper,
which runs `ace cron run <cadence>` (`saq/cron_tasks.py`).

## Adding a task

Drop an executable into the cadence directory. That's all — nothing needs registering.

- It must be a regular file with the executable bit set (`chmod 755`, and make sure git records
  it: `git ls-files -s` should show `100755`). Non-executable files are skipped silently (debug log).
- Files starting with `.` and names ending in `~`, `.bak`, `.orig`, `.disabled` or `.md` are never
  run, so a task can be switched off by renaming it to `<name>.disabled`.
- The file name is the task name; keep it stable (it names the log and the alert grouping key).
- Core tasks start with `source /opt/ace/bin/initialize-environment.sh`, which activates the venv,
  sets `SAQ_HOME` and `cd`s into it, so `ace` and relative `data/...` paths work.
- Exit non-zero on failure. Doing nothing (e.g. a directory that does not exist yet) is success.

### Tasks run in parallel and in no particular order

All tasks for a cadence start at once, at most `service_cron.max_parallel_tasks` at a time
(the number of cpus when unset; `ace cron run <cadence> --max-parallel N` overrides it). A task
must not depend on another task in the same directory having run first. Steps that must happen in
order belong in **one** script — for example `hourly/crash-reports` runs `ace crash prune`, then
`index`, then `sync`, and `daily/rotate-logs` rotates logs before it compresses and expires them.

A failing task does not stop the others.

### Tasks that must run on one node

Every node runs every task. A task that changes shared state (database DDL, a shared bucket, an
external upload) must exit 0 unless `ACE_IS_PRIMARY_NODE` is `1`. Shell tasks check the variable
directly, defaulting to `1` so that a single-node install needs no setting; Python code calls
`is_primary_node()` (`saq/database/util/node.py`). `bin/manage-email-archive-partitions.sh`, run
by `weekly/email-archive-partitions`, is an example.

## Integrations

An enabled integration adds tasks by shipping the same layout in its own directory:

```
integrations/<name>/etc/cron/daily/<task>
```

Tasks of disabled integrations (`ace integration disable <name>`) are not run. See
`integrations.example/example/etc/cron/daily/example-task`.

## Logs and monitoring

Every task runs through `bin/run-cron-job` with the slug `<cadence>-<task>` (core) or
`<cadence>-<integration>-<task>` (integration), so each task gets:

- its own log, `data/logs/<slug>-<date>.log`
- its own structured outcome record (exit code, duration, node, and the output tail on failure)
  on fluent-bit tag `cron-jobs`

The outer `<cadence>-maintenance` job still produces its own log and record: a one-line summary per
task, and an exit code of 1 if any task failed (or was skipped because the service was shutting
down).

On SIGTERM/SIGINT the runner starts no new tasks and forwards the signal to the running ones.

## Seeing what will run

```bash
ace cron list daily            # source, task, slug and path of everything that would run
ace cron run daily             # run them now
```
