"""CLI execution service (ACE API v2, docs/GUI_CLI.md).

A run is one row of cli_executions per node. The user-facing API (POST /cli/executions) writes the
rows and asks each node's engine API to start its own (POST /engine/cli/{id}). That node claims the
row and runs `ace <command>` as a child process: the CLI entry point itself, so the GUI runs exactly
the code a shell would. The output is written back to the row as it arrives.

The sync functions run through run_db_in_thread and commit their own get_db() work, because the
node that runs a command reads the row from its own connection.
"""

import asyncio
import logging
import os
import shlex
import signal
import sys
from collections.abc import Callable

import requests
from fastapi import HTTPException
from sqlalchemy import func, select, text, update
from sqlalchemy.orm import defer

import ace_api
from aceapi_v2.cli.schemas import CliExecutionRead, CliExecutionSummary, CliNodeRead
from aceapi_v2.common.listing import InvalidCursor, decode_cursor, encode_cursor
from aceapi_v2.sync import run_db_in_thread
from saq.constants import ENV_ACE_LOG_CONFIG_PATH
from saq.database.model import CliExecution, Nodes
from saq.database.pool import get_db
from saq.engine.node_manager.distributed_node_manager import translate_node
from saq.environment import get_base_dir, get_global_runtime_settings
from saq.error.reporting import log_loop_exception, log_peer_unavailable
from saq.sandbox.launcher import EXIT_KILLED
from saq.sandbox.runner import LAUNCHER, LAUNCHER_DEADLINE_GRACE, LAUNCHER_STOP_SECONDS, sandbox_python

logger = logging.getLogger(__name__)

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_TIMED_OUT = "timed_out"
STATUS_FAILED = "failed"
STATUS_ABANDONED = "abandoned"

# what is kept of a run's output; the rest is read and dropped so the child never blocks on a pipe
MAX_OUTPUT_BYTES = 1024 * 1024
# how often a running command's output so far is written to its row, for the page to show
OUTPUT_FLUSH_SECONDS = 2.0
# a pending or running row this long past its timeout belongs to a run nothing is watching any more
# (the node's API was killed mid-run, or the dispatch never happened). Longer than stopping a run takes
# (TERM_GRACE_SECONDS + LAUNCHER_STOP_SECONDS + KILL_WAIT_SECONDS + OUTPUT_FLUSH_SECONDS), so a run that
# is still being stopped is not taken for one
STALE_GRACE_SECONDS = 180
# the dispatch only asks the node to start the run, so it returns at once
DISPATCH_TIMEOUT = (10, 30)
# a stopped command gets SIGTERM, so ACE's own shutdown runs (an engine started this way stops its
# workers, releases its locks and marks its node stopped), and this long to finish it before the launcher
# kills everything it started. Longer than any service takes, as docker's stop_grace_period is: SIGTERM
# reaches only the command's own group, so an engine stops a worker waiting on a module's subprocess
# itself, and its shutdown watchdog ends it at shutdown_deadline_seconds plus WATCHDOG_GRACE (95 seconds)
TERM_GRACE_SECONDS = 100
# how long a killed launcher gets to be reaped
KILL_WAIT_SECONDS = 10
# each run is a whole `ace` process in http-api-engine, the container the engines transfer work
# through, so a node runs only this many at once and refuses the rest
MAX_RUNNING_PER_NODE = 3

READ_CHUNK_SIZE = 64 * 1024

# global options (before the subcommand) choose the config, the user, a password prompt or pdb;
# none of that is the GUI user's to choose, so only help is allowed in front of the subcommand
ALLOWED_LEADING_OPTIONS = ("-h", "--help")

# options whose value is a secret. The command is stored and logged as typed, and it can't be
# redacted because the stored command is what the node runs, so these are refused instead; with no
# terminal, a prompt for the secret isn't possible either. --password is accepted by `user add` and
# by `encryption set|test|encrypt|decrypt`; -p and --value are `encryption set|test -p` and
# `encryption config set --value`.
SECRET_OPTIONS = ("--password",)
SECRET_OPTIONS_BY_COMMAND = {
    "encryption": ("--password", "--value", "-p"),
    "enc": ("--password", "--value", "-p"),
}


def parse_command(command: str) -> list[str]:
    """The argv after `ace` for a command line typed into the GUI. Raises ValueError."""
    argv = shlex.split(command)
    if argv and argv[0] == "ace":
        argv = argv[1:]

    if not argv:
        raise ValueError("enter a command, e.g. `node list`")

    if argv[0].startswith("-") and argv[0] not in ALLOWED_LEADING_OPTIONS:
        raise ValueError(f"global option {argv[0]} is not supported here: start with the command name")

    secret_options = SECRET_OPTIONS_BY_COMMAND.get(argv[0], SECRET_OPTIONS)
    for token in argv[1:]:
        if token == "--":
            break
        if _names_secret_option(token, secret_options):
            raise ValueError(
                f"{token.split('=')[0]} takes a secret, and a command run here is stored and logged as "
                "typed: set secrets on the Secrets or Users page, or from a shell")

    return argv


def _names_secret_option(token: str, secret_options: tuple[str, ...]) -> bool:
    if token.startswith("--"):
        # argparse accepts any unambiguous prefix of a long option (--pass for --password)
        name = token.split("=", 1)[0]
        return len(name) > 2 and any(o.startswith(name) for o in secret_options if o.startswith("--"))
    # a short option may carry its value attached (-psecret)
    return any(token.startswith(o) for o in secret_options if not o.startswith("--"))


#
# nodes
#

def list_nodes() -> list[CliNodeRead]:
    rows = get_db().execute(select(Nodes).order_by(Nodes.name)).scalars().all()
    return [CliNodeRead(id=n.id, name=n.name, status=n.status, is_primary=n.is_primary,
                        last_update=n.last_update) for n in rows]


def _resolve_nodes(node_ids: list[int] | None) -> list[Nodes]:
    session = get_db()
    if node_ids is None:
        primary = session.execute(select(Nodes).where(Nodes.is_primary.is_(True))).scalars().first()
        if primary is None:
            raise HTTPException(status_code=409, detail="there is no primary node: select the node to run on")
        return [primary]

    unique_ids = sorted(set(node_ids))
    nodes = session.execute(select(Nodes).where(Nodes.id.in_(unique_ids))).scalars().all()
    missing = sorted(set(unique_ids) - {n.id for n in nodes})
    if missing:
        raise HTTPException(status_code=404, detail=f"unknown node id(s): {missing}")
    return sorted(nodes, key=lambda n: n.name)


#
# rows
#

def create_executions(user_id: int, username: str, argv: list[str], node_ids: list[int] | None,
                      timeout_seconds: int) -> list[int]:
    """One pending row per node, committed, so each node can read its row."""
    session = get_db()
    nodes = _resolve_nodes(node_ids)
    command = shlex.join(argv)

    executions = [CliExecution(user_id=user_id, username=username, node_id=node.id, command=command,
                               status=STATUS_PENDING, timeout_seconds=timeout_seconds)
                  for node in nodes]
    session.add_all(executions)
    session.commit()

    for execution, node in zip(executions, nodes):
        logger.info("AUDIT: user %s requested cli execution %s on node %s: ace %s",
                    username, execution.id, node.name, command,
                    extra={"cli_execution_id": execution.id, "node": node.name, "user": username})

    return [e.id for e in executions]


def expire_stale_executions() -> int:
    """Mark the runs nothing will finish as abandoned. Only pending and running rows can match and
    there are only ever a handful (i_cli_execution_status), so this is a small update."""
    session = get_db()
    deadline = func.timestampadd(
        text("SECOND"), CliExecution.timeout_seconds + STALE_GRACE_SECONDS, CliExecution.created_at)
    stale = session.execute(
        select(CliExecution.id, Nodes.name)
        .join(Nodes, Nodes.id == CliExecution.node_id)
        .where(CliExecution.status.in_((STATUS_PENDING, STATUS_RUNNING)), deadline < func.now())).all()
    if not stale:
        return 0

    stale_ids = [execution_id for execution_id, _ in stale]
    result = session.execute(
        update(CliExecution)
        # the status condition again: a run that finished since the select keeps its result
        .where(CliExecution.id.in_(stale_ids), CliExecution.status.in_((STATUS_PENDING, STATUS_RUNNING)))
        .values(status=STATUS_ABANDONED, finished_at=func.now(),
                error="the node stopped reporting on this run before it finished"))
    session.commit()
    node_names = sorted({name for _, name in stale})
    logger.warning("marked cli execution(s) %s abandoned: node(s) %s stopped reporting on them",
                   stale_ids, node_names,
                   extra={"cli_execution_ids": stale_ids, "nodes": node_names})
    return result.rowcount


def _summary_fields(execution: CliExecution, node_name: str) -> dict:
    return dict(
        id=execution.id, user_id=execution.user_id, username=execution.username, node_id=execution.node_id,
        node_name=node_name, command=execution.command, status=execution.status,
        exit_code=execution.exit_code, error=execution.error,
        timeout_seconds=execution.timeout_seconds, created_at=execution.created_at,
        started_at=execution.started_at, finished_at=execution.finished_at)


def _select_with_node_name():
    return select(CliExecution, Nodes.name).join(Nodes, Nodes.id == CliExecution.node_id)


def get_executions(execution_ids: list[int]) -> list[CliExecutionRead]:
    expire_stale_executions()
    rows = get_db().execute(
        _select_with_node_name().where(CliExecution.id.in_(execution_ids)).order_by(CliExecution.id)).all()
    return [CliExecutionRead(**_summary_fields(e, node_name),
                             output=e.output, output_truncated=e.output_truncated)
            for e, node_name in rows]


def get_execution(execution_id: int) -> CliExecutionRead | None:
    executions = get_executions([execution_id])
    return executions[0] if executions else None


def fetch_execution_page(cursor: str | None, limit: int) -> tuple[list[CliExecutionSummary], str | None]:
    """Newest first, by keyset on id. The output (up to MAX_OUTPUT_BYTES a row) is never loaded."""
    expire_stale_executions()
    statement = (_select_with_node_name().options(defer(CliExecution.output, raiseload=True))
                 .order_by(CliExecution.id.desc()).limit(limit + 1))
    if cursor is not None:
        def _parse(payload: dict) -> int:
            if payload["o"] != "id_desc":
                raise InvalidCursor("cursor belongs to another order")
            return int(payload["k"][0])

        statement = statement.where(CliExecution.id < decode_cursor(cursor, _parse))

    rows = get_db().execute(statement).all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_cursor = encode_cursor(o="id_desc", k=[rows[-1][0].id])

    return [CliExecutionSummary(**_summary_fields(e, node_name))
            for e, node_name in rows], next_cursor


def _finish(execution_id: int, status: str, *, exit_code: int | None = None,
            output: str | None = None, output_truncated: bool = False,
            error: str | None = None, only_if_pending: bool = False) -> bool:
    session = get_db()
    statement = update(CliExecution).where(CliExecution.id == execution_id)
    if only_if_pending:
        statement = statement.where(CliExecution.status == STATUS_PENDING)
    values = dict(status=status, exit_code=exit_code, error=error, finished_at=func.now())
    if output is not None:
        values.update(output=output, output_truncated=output_truncated)
    result = session.execute(statement.values(**values))
    session.commit()
    return result.rowcount == 1


#
# dispatch (on the node that took the request)
#

def dispatch_execution(execution_id: int) -> None:
    """Ask the execution's node to start it. A node that cannot be asked fails the row here; a
    node that was asked but did not answer may still have claimed it, so only a still-pending row
    is failed."""
    row = get_db().execute(
        select(Nodes.name, Nodes.location)
        .join(CliExecution, CliExecution.node_id == Nodes.id)
        .where(CliExecution.id == execution_id)).one()
    node_name, location = row
    context = f"starting cli execution {execution_id} on node {node_name} ({location})"

    try:
        ace_api.start_cli_execution(execution_id, remote_host=translate_node(location), timeout=DISPATCH_TIMEOUT)
        return
    except requests.HTTPError as e:
        detail = e.response.text if e.response is not None else str(e)
        if e.response is not None and e.response.status_code == 429:
            # the node is running its limit already: an expected answer, recorded on the run for
            # the user, not an error to report
            logger.info("%s: node busy: %s", context, detail, extra={"cli_execution_id": execution_id, "node": node_name})
        else:
            log_loop_exception(e, context)
        error = f"node {node_name} refused the run: {detail}"
    except Exception as e:
        if not log_peer_unavailable(e, context):
            log_loop_exception(e, context)
        error = f"unable to reach node {node_name} at {location}: {e}"

    _finish(execution_id, STATUS_FAILED, error=error, only_if_pending=True)


#
# the run (on the node it names)
#

def claim_execution(execution_id: int) -> tuple[list[str], int]:
    """Take a pending execution of this node's: its argv and timeout. 404 for an unknown id, 409
    for another node's or one already claimed, 429 while MAX_RUNNING_PER_NODE runs are running."""
    session = get_db()
    row = session.execute(
        select(CliExecution.command, CliExecution.timeout_seconds, CliExecution.status, Nodes.name)
        .join(Nodes, Nodes.id == CliExecution.node_id)
        .where(CliExecution.id == execution_id)).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="cli execution not found")

    command, timeout_seconds, status, node_name = row
    local_node = get_global_runtime_settings().saq_node
    if node_name != local_node:
        raise HTTPException(status_code=409, detail=f"cli execution {execution_id} is for node {node_name}, this is {local_node}")

    # the node's row lock makes count-then-claim atomic between this node's API workers; nothing
    # else that locks the nodes row touches cli_executions, so the order can't deadlock
    node_id = session.execute(
        select(Nodes.id).where(Nodes.name == local_node).with_for_update()).scalar_one()
    running = session.execute(
        select(func.count()).select_from(CliExecution)
        .where(CliExecution.node_id == node_id, CliExecution.status == STATUS_RUNNING)).scalar_one()
    if running >= MAX_RUNNING_PER_NODE:
        session.rollback()
        logger.info("refused cli execution %s: %d already running on %s", execution_id, running, local_node,
                    extra={"cli_execution_id": execution_id, "node": local_node})
        raise HTTPException(status_code=429, detail=(
            f"{running} cli executions are already running on {local_node}; "
            f"wait for one to finish (at most {MAX_RUNNING_PER_NODE} at once)"))

    result = session.execute(
        update(CliExecution)
        .where(CliExecution.id == execution_id, CliExecution.status == STATUS_PENDING)
        .values(status=STATUS_RUNNING, started_at=func.now()))
    session.commit()
    if result.rowcount != 1:
        raise HTTPException(status_code=409, detail=f"cli execution {execution_id} is {status}, not pending")

    logger.info("running cli execution %s: ace %s", execution_id, command,
                extra={"cli_execution_id": execution_id, "node": local_node})
    return shlex.split(command), timeout_seconds


def _record_output(execution_id: int, output: str, output_truncated: bool) -> None:
    session = get_db()
    session.execute(
        update(CliExecution)
        .where(CliExecution.id == execution_id, CliExecution.status == STATUS_RUNNING)
        .values(output=output, output_truncated=output_truncated))
    session.commit()


def cli_command_line(argv: list[str]) -> list[str]:
    return [sys.executable, os.path.join(get_base_dir(), "ace"), *argv]


def supervised_command_line(command: list[str], timeout_seconds: int) -> list[str]:
    """command under the sandbox launcher, a child subreaper: whatever the command starts, in whatever
    session or group, is killed when it exits or is stopped, so the API signals only the launcher.

    --unconfined: the command runs as a shell's would, with no Landlock domain. setpriv gives the
    launcher SIGTERM as its parent-death signal: if the API worker dies without stopping it (SIGKILL,
    OOM), the command still gets its graceful stop instead of running unwatched."""
    return ["setpriv", "--pdeathsig", "TERM", "--",
            sandbox_python(), "-I", "-S", LAUNCHER,
            f"--deadline={timeout_seconds + LAUNCHER_DEADLINE_GRACE.total_seconds():g}",
            f"--term-grace={TERM_GRACE_SECONDS}",
            "--unconfined",
            "--", *command]


def _child_environment() -> dict[str, str]:
    # the API's logging config would send the command's log records to the API's log; without it
    # the CLI logs to the console, which is the output the user is waiting for
    env = dict(os.environ)
    env.pop(ENV_ACE_LOG_CONFIG_PATH, None)
    return env


async def _stop(execution_id: int, process: asyncio.subprocess.Process, append: Callable[[bytes], None]) -> None:
    """Tell the launcher to stop the command: it SIGTERMs the command's group, gives it
    TERM_GRACE_SECONDS, then kills everything the command started and exits. What it prints meanwhile
    goes to append. Bounded: at most TERM_GRACE_SECONDS + LAUNCHER_STOP_SECONDS + KILL_WAIT_SECONDS
    + OUTPUT_FLUSH_SECONDS."""
    if process.returncode is not None:
        return

    async def _read_to_eof():
        while chunk := await process.stdout.read(READ_CHUNK_SIZE):
            append(chunk)

    # read while it stops: a command that writes more than the pipe holds would block on it until
    # it is killed, and the launcher's own messages after it
    reader = asyncio.ensure_future(_read_to_eof())
    try:
        await _signal_launcher(execution_id, process)
    finally:
        try:
            # bounded, as a launcher that had to be killed leaves whatever the command started holding the pipe
            await asyncio.wait_for(reader, timeout=OUTPUT_FLUSH_SECONDS)
        except TimeoutError:
            pass  # wait_for cancelled the reader; the rest of the output is not worth waiting for


async def _signal_launcher(execution_id: int, process: asyncio.subprocess.Process) -> None:
    try:
        process.send_signal(signal.SIGTERM)
        exit_code = await asyncio.wait_for(process.wait(), timeout=TERM_GRACE_SECONDS + LAUNCHER_STOP_SECONDS)
    except ProcessLookupError:
        return  # it exited since the check
    except TimeoutError:
        # the launcher is stuck; what the command started is reparented to init once it dies, and nothing
        # kills it
        logger.exception("cli execution %s: launcher %s did not exit %s seconds after SIGTERM, killing it; "
                         "what the command started may be left running",
                         execution_id, process.pid, TERM_GRACE_SECONDS + LAUNCHER_STOP_SECONDS,
                         extra={"cli_execution_id": execution_id, "pid": process.pid})
    else:
        if exit_code == EXIT_KILLED:
            # an engine killed this way kept its locks and left its node running
            logger.warning("cli execution %s: the command or what it started was still running after SIGTERM "
                           "and was killed (the end of the run's output says which)", execution_id,
                           extra={"cli_execution_id": execution_id})
        return

    try:
        process.kill()
        # SIGKILL cannot be ignored, so only an unkillable (D state) launcher takes this long
        await asyncio.wait_for(process.wait(), timeout=KILL_WAIT_SECONDS)
    except ProcessLookupError:
        pass  # it exited after all
    except TimeoutError:
        logger.warning("cli execution %s: launcher %s did not exit after SIGKILL", execution_id, process.pid,
                       extra={"cli_execution_id": execution_id})


async def run_execution(execution_id: int, argv: list[str], timeout_seconds: int) -> None:
    """Run a claimed execution to the end and record how it went. Never raises: it runs after the
    response, where nothing would see it."""
    loop = asyncio.get_running_loop()
    output = bytearray()
    truncated = False
    process = None
    status = STATUS_FAILED
    exit_code = None
    error = None

    def _text() -> str:
        return output.decode("utf-8", errors="replace")

    def _append(chunk: bytes) -> None:
        nonlocal output, truncated
        room = MAX_OUTPUT_BYTES - len(output)
        if len(chunk) > room:
            truncated = True
        output += chunk[:max(room, 0)]

    try:
        try:
            process = await asyncio.create_subprocess_exec(
                *supervised_command_line(cli_command_line(argv), timeout_seconds),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=get_base_dir(),
                env=_child_environment(),
                start_new_session=True)
        except OSError as e:
            log_loop_exception(e, f"starting cli execution {execution_id}")
            error = f"unable to start the command: {e}"
            return

        deadline = loop.time() + timeout_seconds
        last_flush = loop.time()
        flushed_size = 0
        timed_out = False

        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                timed_out = True
                break

            try:
                chunk = await asyncio.wait_for(
                    process.stdout.read(READ_CHUNK_SIZE), timeout=min(remaining, OUTPUT_FLUSH_SECONDS))
            except TimeoutError:
                chunk = None  # nothing new this interval

            if chunk == b"":
                break  # EOF: the command (and everything it started) closed its output

            if chunk:
                _append(chunk)

            if len(output) != flushed_size and loop.time() - last_flush >= OUTPUT_FLUSH_SECONDS:
                await run_db_in_thread(_record_output, execution_id, _text(), truncated)
                flushed_size = len(output)
                last_flush = loop.time()

        if not timed_out:
            try:
                exit_code = await asyncio.wait_for(process.wait(), timeout=max(deadline - loop.time(), 0.1))
            except TimeoutError:
                timed_out = True  # closed its output but kept running

        if timed_out:
            await _stop(execution_id, process, _append)
            status = STATUS_TIMED_OUT
            error = f"stopped after its timeout of {timeout_seconds} seconds"
        else:
            status = STATUS_COMPLETED

    except asyncio.CancelledError:
        # the API worker is shutting down; the run stops with it. Shielded so a second cancellation
        # can't cut the stop short; if the worker exits first, the parent-death signal stops it.
        status = STATUS_ABANDONED
        error = "the node's API stopped while the command was running"
        if process is not None:
            await _shielded_stop(execution_id, process, _append)
        raise
    except Exception as e:
        log_loop_exception(e, f"running cli execution {execution_id}")
        error = f"internal error running the command: {e}"
        if process is not None:
            await _shielded_stop(execution_id, process, _append)
    finally:
        logger.info("cli execution %s finished: %s (exit code %s)", execution_id, status, exit_code,
                    extra={"cli_execution_id": execution_id})
        try:
            # shielded: during a cancellation this is the only record that the run ended
            await asyncio.shield(run_db_in_thread(
                _finish, execution_id, status, exit_code=exit_code, output=_text(),
                output_truncated=truncated, error=error))
        except Exception as e:
            log_loop_exception(e, f"recording the end of cli execution {execution_id}")


async def _shielded_stop(execution_id: int, process: asyncio.subprocess.Process,
                         append: Callable[[bytes], None]) -> None:
    """_stop() on a path that must not raise, and must not be cut short by a cancellation."""
    try:
        await asyncio.shield(_stop(execution_id, process, append))
    except asyncio.CancelledError:
        # cancelled again while stopping: the shielded stop carries on by itself, and the
        # cancellation still belongs to the task
        raise
    except Exception as e:
        log_loop_exception(e, f"stopping cli execution {execution_id}")
