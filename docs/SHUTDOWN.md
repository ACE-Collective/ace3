# Shutdown

How an ACE node stops, and why it stops the way it does.

## The problem this solves

Shutting a node down used to fill the logs with errors. The cause was not the error
handling: it was that **no ACE process ever received SIGTERM**, so nothing shut down at
all — every container was SIGKILLed by Docker ten seconds after the stop began.

`docker/startup/start.sh` ran the ACE command *without* `exec`, so PID 1 in every
long-running container was a bash shell with the Python process as a foreground child. A
non-interactive bash does not forward SIGTERM to a foreground child. Docker signalled
bash; bash did nothing; ten seconds later the cgroup was torn down.

Everything else followed from that. Workers died mid-analysis holding database locks that
nobody released for `lock_timeout_seconds` (5 minutes), so their work looked claimed and
sat idle. The engine never reached the line that marks its node `stopped`, so peers kept
routing to it. Every process that outlived a peer by a second logged an exception about
it — and each of those wrote an error-report file and emitted a monitor event, which the
database pool and `report_exception()` amplified further.

## The governing invariant

**ACE always exits before Docker's SIGKILL fires.**

Every process has an internal shutdown deadline strictly shorter than its container's
`stop_grace_period`, and escalates on its own rather than waiting to be killed:

| Step | Mechanism |
|---|---|
| Ask nicely | shutdown flag; loops and modules check it and return |
| Cancel | in-flight analysis is cancelled so it unwinds through its `finally` blocks |
| Kill children | workers that ignore the flag past the budget are SIGKILLed as a process tree |
| Force exit | a watchdog thread calls `os._exit(0)` at the deadline regardless |

If any of these is reached, the ones before it failed — but the container still stops on
time, and the node still tells the cluster it is going away.

## The control point

`saq/shutdown.py` holds one `ShutdownCoordinator` per process. Library code anywhere can
ask the general question:

```python
from saq.shutdown import is_shutting_down

if is_shutting_down():
    ...
```

That predicate is what lets ACE distinguish "the database call failed" from "the database
call failed because we are shutting down" — a distinction it previously could not make,
which is why both were logged as errors.

Three rules about it:

- **Signal handlers only set the flag.** They never call `stop()`. A handler runs on the
  main thread, so calling `stop()` there deadlocks any service whose `stop()` joins the
  threads the main thread is already joining.
- **SIGTERM and SIGINT mean the same thing.** Docker sends the first, an operator at a
  terminal sends the second. (Until this change SIGTERM meant *abrupt* and only SIGINT
  was graceful, so the graceful path never ran in production.)
- **The flag is an `mp.Event` created before any fork**, so forked engine workers observe
  a shutdown requested by the parent.

`get_shutdown_coordinator()` also offers `sleep()` (returns early on shutdown),
`deadline_remaining()`, and `register()` for ordered shutdown hooks. `run_bounded()` runs
a call with a timeout so one wedged step cannot strand the rest.

## What happens to in-flight analysis

It is **abandoned and requeued**, not finished.

Each worker cancels the analysis it is running, via the same `cancel_analysis()` mechanism
the lock-lost path uses. The executor's analysis loop stops at its next check and unwinds
through its own `finally` blocks, releasing the work item's lock and clearing its tracking
record. The workload row survives, unlocked, and another node claims it immediately.

This is the difference between abandoning and being killed. A SIGKILLed worker leaves the
same workload row behind, but with a lock nobody releases for five minutes.

After the workers exit, the engine clears any locks still owned by this node
(`clear_node_locks`) and only then marks the node `stopped` — last, so peers stop routing
work here once there is genuinely nothing left to receive it.

## Processes that will not stop cleanly

An analysis module in a CPU loop, or blocked on a socket with no timeout, cannot be asked
to stop. Three backstops handle it, and all three now keep running *during* shutdown:

| Backstop | Where |
|---|---|
| `AnalysisModuleMonitor` calls `os._exit(1)` past `maximum_analysis_time` | `saq/engine/executor.py` |
| `WorkerManager.check()` SIGKILLs the process tree on timeout or memory limit | `saq/engine/worker_manager.py` |
| The coordinator's watchdog force-exits the process at the deadline | `saq/shutdown.py` |

The second one used to stop the moment the controller loop broke for shutdown — exactly
when a stuck module is most likely to be what is holding everything up.
`supervise_shutdown()` keeps it running while it waits.

Workers are now waited on **together against one shared budget**, not one at a time for 60
seconds each. With a pool of N workers the old behavior had a worst case of N × 60s
against a 10 second grace period.

## Draining a node

Draining is separate from stopping, and it is what makes a shutdown orderly across a
cluster. It takes the node out of rotation *before* anything stops: collectors pause and
flush what they have already accepted, outstanding delayed analysis moves to a node that
can still run it, and submissions are refused with 503.

```
starting → running → draining_collectors → draining → drained → stopped
```

The node advances through those phases on its own, driven by the engine's drain routines.
Two things start it, and they apply the same transitions (defined once in
`saq.constants.NODE_TRANSITION_DRAIN`):

```bash
ace node status                          # status, expected state, workload, collectors
ace node drain --wait --timeout 300      # from the node itself
ace node resume                          # cancel a drain
```
```
POST /api/v2/nodes/{id}/drain            # from the GUI or a remote operator
POST /api/v2/nodes/{id}/resume
```

`nodes.status` is what the node **is**; `nodes.expected_state` is what an operator says it
**should** be. A drain sets `expected_state` to `offline`, which is how monitoring tells a
node that was deliberately taken down from one that crashed — both end up `stopped`.

## Stopping a node

```bash
bin/ace-shutdown.sh                 # drain (up to 300s), then stop
bin/ace-shutdown.sh --fast          # skip the drain
bin/ace-shutdown.sh --down          # docker compose down instead of stop
```

Do not pass `-t` to `docker compose stop`. It replaces the per-service
`stop_grace_period` values with a single number for everything, which would give the
engine the same few seconds as a stateless proxy.

Grace periods are sized per service in `docker-compose.yml`, and each process is
configured to exit well inside its own (`shutdown_deadline_seconds` on the service config,
`reload-mercy` for uwsgi, `--timeout-graceful-shutdown` for uvicorn):

| Container(s) | Grace |
|---|---|
| `ace` (engine) | 120s |
| `ace-db`, `ace-db-readonly` | 90s |
| web tiers, `qdrant`, `rabbitmq`, celery sidecars | 60s |
| supporting ACE services | 45s |
| proxies, `redis`, `fluent-bit` | 30s |

Compose's existing `depends_on` graph already stops things in a sensible order: the web
tier, collectors and support services stop before the engine, and the engine's own
dependencies stop after it.

## Adding a service

Services are launched by `ace service start <name>`, which owns the whole lifecycle (see
`saq/cli/commands/service.py`). A service must:

- return from `stop()` reasonably quickly, and not join anything without a timeout;
- not install its own SIGTERM or SIGINT handler;
- check `is_shutting_down()` (or the coordinator's `sleep()`) in any long-running loop;
- set `shutdown_deadline_seconds` in its config block if the default 20s is not enough,
  keeping it below the container's `stop_grace_period`.

In a loop's catch-all handler, use `log_loop_exception()` rather than
`logging.error()` + `report_exception()`:

```python
from saq.error.reporting import log_loop_exception

while not shutting_down:
    try:
        work()
    except Exception as e:
        log_loop_exception(e, "doing work")
```

During shutdown that logs at INFO and skips the error report. Outside shutdown it behaves
as before. This matters more than it looks: peers disappear in dependency order, so
without it every loop in every worker in every service reports an error per iteration for
the last few seconds of its life.

## Verifying

```bash
time bin/ace-shutdown.sh            # must finish inside the grace periods
docker compose logs | grep -Ei "error|traceback|DEADLOCK STATEMENT" | wc -l
docker compose up -d
```

The best single regression signal is on the way back up: the engine logs
`clearing N locks from previous execution` at startup. After a clean shutdown that count
should be **zero**, because the node released its own locks on the way out.
