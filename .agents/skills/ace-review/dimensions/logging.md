# Logging reviewer

The maintainer debugs production from logs, without a shell on the node. You check that every failure the change can produce is visible, reported and traceable to the thing that failed. Don't review message formatting at all: f-string, `%s` and `.format()` are all fine.

Read first: `CLAUDE.md` § Engineering values → Logging, and `saq/error/reporting.py`, in particular `ErrorReportHandler`, `log_loop_exception` and `log_peer_unavailable`.

## Look for

**Caught exceptions logged without their traceback.** Look at every `except` the change adds or modifies.
- If it logs, it must log at ERROR with the traceback: `logging.exception(...)`, `exc_info=` at ERROR, or `log_loop_exception(e, "<context>")`. The root logger's `ErrorReportHandler` turns any of those into the error report and the monitor event.
- Flag `logging.error(...)` without `exc_info`, `logging.warning(str(e))` and `print(...)` used instead.
- A long-running loop's catch-all uses `log_loop_exception()`, which is quiet during shutdown. `logging.exception()` there logs an ERROR line per iteration while the peers go away.
- A connection failure to a peer (redis, qdrant, a remote node) is allowed to use `log_peer_unavailable(e, context)` and fall through.

**Silenced failures.**
- `except: pass`, `except Exception: pass`, or `except ...: return None`/`continue` with no log and no comment saying why silence is right.
- A bare `except:` is always a finding.
- A re-raise that drops the cause: `raise X(...)` inside an `except` with no `from e`.
- `traceback.print_exc()`.
- Deliberate silence on a never-raise path (crash reporting, shutdown) is fine with a comment.

**Context strings and identifiers.** Would someone grepping the logs be able to find the alert, observable, file, row or crash that failed?
- The message, or the `context` argument to `log_loop_exception`, should carry the uuid or id.
- New log records should carry identifiers, preferably in `extra={}` (`saq/logging.py` turns those into Splunk fields; see the "analysis module crash recorded" record in `saq/crash_report.py`).
- Flag "failed to process item" when the item isn't identified.

**Levels.**
- A failure an operator must act on, logged at DEBUG or INFO.
- An expected, routine condition logged at ERROR every time it happens (alert fatigue).
- Per-item INFO or WARNING inside a hot loop that would flood the logs at production volume.
- A significant state change (a work item claimed, retired or requeued, a fallback taken, a feature disabled) with no INFO record at all.

**Secrets.** Passwords, API keys, tokens, auth headers or full connection strings written to a log.

## Calibration

- A silent `except` on a path that matters, or secrets in a log, is a blocker or a fix-first, depending on how often the path runs.
- A caught exception logged without its traceback is fix-first.
- A missing identifier in a message is fix-first if the failure would be hard to trace without it, otherwise a nit.
- Pre-existing logging debt in functions the change edits goes under `origin: pre-existing`. The tree has a lot of it, including dozens of bare `except:` and silent `except: pass` blocks.
