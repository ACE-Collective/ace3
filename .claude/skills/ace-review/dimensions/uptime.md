# Uptime reviewer

ACE runs continuously and is never down for more than a few minutes. You look for anything in the change that can take a process down, hang it, keep it from stopping or restarting cleanly, or quietly stop doing its job without anyone noticing. This is the highest-priority dimension.

Read first: `CLAUDE.md` § Engineering values → Uptime, and § Significant Subsystems → Shutdown. If the change touches services, also read `docs/SERVICES.md` and `docs/SHUTDOWN.md`. If it touches the DDL or partitioned tables, read `docs/DATABASE_PARTITIONS.md`.

## Look for

**Hangs and unbounded waits.**
- `thread.join()`, `process.join()`, `queue.get()`, `event.wait()`, `lock.acquire()` or `subprocess.run()` without a timeout on a run, stop or shutdown path.
- A network or HTTP call with no timeout (requests, httpx, boto3, pymysql, redis, celery `.get()`).
- An unbounded join is acceptable only with a comment naming what bounds it. For example, a service's `wait()` may join its threads without a timeout because `ace service start` bounds the whole call with a deadline, but it needs a comment saying so.

**Shutdown.**
- A service or worker that installs its own SIGTERM/SIGINT handler. Handlers belong to `saq/shutdown.py`.
- A long-running loop that doesn't check `is_shutting_down()`, or that sleeps for long stretches without waking on the shutdown event.
- Work abandoned at shutdown that isn't requeued or released (locks, claimed rows, leases).

**Crash loops and process death.**
- An exception that escapes a service's main loop. Every iteration needs a catch-all that goes through `log_loop_exception()`, so one bad item doesn't kill the service.
- Startup that fails hard on a transient dependency, such as the database or redis not being ready yet.
- `sys.exit` or `os._exit` outside the designated places.
- Code on the crash, watchdog or shutdown path (`saq/crash_report.py`, `saq/shutdown.py`, monitors) that can raise. That path must never raise.

**Database safety on a live system.**
- A migration that rewrites or copies a large table, adds a non-nullable column without a server default to a big table, or builds an index on a big table in a blocking way.
- Splitting a populated partition: `REORGANIZE PARTITION`, or `PARTITION BY` on a populated table.
- An unbounded `DELETE`/`UPDATE` on a table that grows. It must be batched by primary key (`saq/cas/index.py`, `saq/database/util/index.py:398`).
- A long transaction held across I/O or a network call.
- A lock taken without `lock_wait_timeout` or a bounded retry.
- Retries that don't use `saq/database/retry.py::execute_with_retry` where a deadlock or lock wait is plausible.
- Time comparisons against stored timestamps made with the application clock (`datetime.now()`) instead of the database's `NOW()`.

**Resource leaks in long-lived processes.** Sessions, connections, file handles, temp dirs or threads created per item and never closed. A module-level cache that grows forever.

**Silent stoppage.** A background thread that dies on an exception and is never restarted or reported. A queue consumer that exits its loop on an error. A "fallback" that permanently disables a feature after one failure without logging it at WARNING or above.

**Deploy safety.**
- A config key added to `saq/configuration/schema.py` as required with no default. An existing deployment fails validation on upgrade.
- A renamed or removed config key with no tolerance for the old one.
- A change to a cross-node or on-disk format with no reader for the old format. For example `saq/crypto` v0/v1: nodes read each other's data during a rolling update.

## Calibration

- An unbounded wait or a migration that locks a big table is a blocker.
- A missing timeout on a call to an internal peer that already has one at the socket level is a fix-first, if anything at all.
- Each finding names the process and the path where it happens. If you can't say which service or command hits the code, it is not an uptime finding.
