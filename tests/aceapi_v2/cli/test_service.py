"""The CLI execution service: command parsing, the row lifecycle and the run itself."""

import asyncio
import logging
import os
import shlex
import signal
import subprocess
import sys
from datetime import datetime

import pytest
from sqlalchemy import select, text

from aceapi_v2.cli import service
from saq.sandbox.runner import LAUNCHER
from saq.configuration.config import get_config
from saq.database.model import CliExecution, Nodes, User
from saq.database.pool import get_db
from saq.environment import get_global_runtime_settings
from saq.shutdown import DEFAULT_SHUTDOWN_DEADLINE, WATCHDOG_GRACE
from tests.saq.helpers import process_is_gone, wait_for_condition


# starts a process in a session of its own, the way a script daemonizes something, and prints its pid
_ESCAPE = ("import subprocess, sys\n"
           "p = subprocess.Popen(['sleep', '60'], start_new_session=True,\n"
           "                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
           "print('escaped', p.pid, flush=True)\n")


def _escaped_pid(output: str) -> int:
    return int(output.split("escaped ")[1].split()[0])


def _kill(pid: int):
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass  # already gone, which is what the caller wants


#
# parse_command
#

@pytest.mark.unit
@pytest.mark.parametrize("command,expected", [
    ("node list", ["node", "list"]),
    ("ace node list", ["node", "list"]),
    ("  cas verify --pool 'my pool'  ", ["cas", "verify", "--pool", "my pool"]),
    ("--help", ["--help"]),
    ("-h", ["-h"]),
    ("ace --help", ["--help"]),
])
def test_parse_command(command, expected):
    assert service.parse_command(command) == expected


@pytest.mark.unit
@pytest.mark.parametrize("command,message", [
    ("", "enter a command"),
    ("ace", "enter a command"),
    ("-u someone node list", "global option -u"),
    ("--config-path /tmp/x.yaml node list", "global option --config-path"),
    ("-D node list", "global option -D"),
    ("node list 'unbalanced", "quotation"),
])
def test_parse_command_rejects(command, message):
    with pytest.raises(ValueError, match=message):
        service.parse_command(command)


@pytest.mark.unit
def test_cli_command_line_runs_the_ace_entry_point():
    argv = service.cli_command_line(["node", "list"])
    assert argv[0] == sys.executable
    assert argv[1].endswith("/ace")
    assert argv[2:] == ["node", "list"]


@pytest.mark.unit
def test_the_command_runs_under_the_launcher():
    argv = service.supervised_command_line(["ace", "node", "list"], 60)
    assert argv[:4] == ["setpriv", "--pdeathsig", "TERM", "--"]
    assert argv[argv.index("-S") + 1] == LAUNCHER
    assert "--deadline=90" in argv  # its timeout plus the launcher's deadline grace
    assert f"--term-grace={service.TERM_GRACE_SECONDS}" in argv
    assert "--unconfined" in argv
    assert argv[argv.index("--", 4) + 1:] == ["ace", "node", "list"]


@pytest.mark.unit
@pytest.mark.parametrize("command", [
    "user add bob bob@example.com --password hunter2",
    "user add bob bob@example.com --password=hunter2",
    "user add bob bob@example.com --pass hunter2",
    "enc set -p hunter2",
    "enc set -phunter2",
    "encryption test --password hunter2",
    "enc config set vendor.api_key --value hunter2",
    "enc config set vendor.api_key --val=hunter2",
])
def test_parse_command_refuses_secrets(command):
    with pytest.raises(ValueError, match="takes a secret"):
        service.parse_command(command)


@pytest.mark.unit
@pytest.mark.parametrize("command", [
    # -p and --value only carry secrets under `encryption`
    "storage list-objects -p some/prefix",
    "config -v gui.listen_port",
    "config --value gui.listen_port",
    "enc config set vendor.api_key --load-from-file /tmp/key",
    "cas verify --pool yara_qa",
    # after --, nothing is an option
    "alert add-observable uuid file_name -- --password",
])
def test_parse_command_allows_options_that_carry_no_secret(command):
    assert service.parse_command(command) == shlex.split(command)


@pytest.mark.integration
def test_the_run_is_stopped_when_its_parent_dies():
    """The parent-death signal setpriv gives the launcher: a command whose API worker dies is stopped,
    and so is what it started in a session of its own, not left to run unwatched (issue 973)."""
    code = _ESCAPE + "import time; time.sleep(60)\n"
    argv = service.supervised_command_line([sys.executable, "-c", code], 60)
    # the parent prints the launcher's pid and the escaped process's, then exits without stopping it
    parent = subprocess.run(
        [sys.executable, "-c",
         "import subprocess, sys\n"
         f"p = subprocess.Popen({argv!r}, stdout=subprocess.PIPE, text=True)\n"
         "print(p.pid, p.stdout.readline().split()[1], flush=True)\n"],
        capture_output=True, text=True, timeout=30, check=True)
    launcher, escaped = (int(pid) for pid in parent.stdout.split())

    try:
        wait_for_condition(lambda: process_is_gone(launcher) and process_is_gone(escaped), timeout=10)
    finally:
        _kill(launcher)
        _kill(escaped)


@pytest.mark.unit
def test_child_environment_drops_the_api_logging_config(monkeypatch):
    monkeypatch.setenv("ACE_LOG_CONFIG_PATH", "etc/logging_configs/ace_logging.yaml")
    assert "ACE_LOG_CONFIG_PATH" not in service._child_environment()


#
# helpers
#

def _clear_primary() -> None:
    session = get_db()
    session.execute(text("UPDATE nodes SET is_primary = 0"))
    session.commit()


def _add_node(name: str, *, is_primary: bool = False, location: str = "remote:443") -> int:
    session = get_db()
    node = Nodes(name=name, location=location, company_id=1, last_update=datetime.now(),
                 is_primary=is_primary, status="running")
    session.add(node)
    session.commit()
    return node.id


def _local_node() -> int:
    # the environment reset may have restored this node's own row
    name = get_global_runtime_settings().saq_node
    node_id = get_db().execute(select(Nodes.id).where(Nodes.name == name)).scalar_one_or_none()
    return node_id if node_id is not None else _add_node(name, location="localhost:443")


def _unittest_user_id() -> int:
    return get_db().execute(select(User.id).where(User.username == "unittest")).scalar_one()


def _create(argv: list[str], node_ids, timeout_seconds: int = 60) -> list[int]:
    return service.create_executions(_unittest_user_id(), "unittest", argv, node_ids, timeout_seconds)


def _row(execution_id: int) -> CliExecution:
    session = get_db()
    session.expire_all()
    return session.get(CliExecution, execution_id)


#
# create / expire / read
#

@pytest.mark.integration
def test_create_defaults_to_the_primary_node(caplog):
    _clear_primary()
    _add_node("node-a")
    primary_id = _add_node("node-b", is_primary=True)

    with caplog.at_level(logging.INFO):
        (execution_id,) = _create(["node", "list"], None)

    row = _row(execution_id)
    assert row.node_id == primary_id
    assert row.status == service.STATUS_PENDING
    assert row.command == "node list"
    assert "AUDIT: user unittest requested cli execution" in caplog.text


@pytest.mark.integration
def test_create_one_row_per_selected_node():
    a = _add_node("node-a")
    b = _add_node("node-b")

    ids = _create(["cas", "verify", "--pool", "my pool"], [b, a, b])

    rows = [_row(i) for i in ids]
    assert sorted(r.node_id for r in rows) == [a, b]
    # quoting survives the round trip through the row
    assert {shlex.split(r.command)[-1] for r in rows} == {"my pool"}


@pytest.mark.integration
def test_create_without_a_primary_node_is_a_conflict():
    _clear_primary()
    _add_node("node-a")
    with pytest.raises(service.HTTPException) as e:
        _create(["node", "list"], None)
    assert e.value.status_code == 409


@pytest.mark.integration
def test_create_with_an_unknown_node_is_not_found():
    a = _add_node("node-a")
    with pytest.raises(service.HTTPException) as e:
        _create(["node", "list"], [a, a + 1000])
    assert e.value.status_code == 404
    assert str(a + 1000) in e.value.detail


@pytest.mark.integration
def test_stale_runs_are_abandoned_when_read():
    a = _add_node("node-a")
    stale, fresh = _create(["node", "list"], [a]) + _create(["node", "list"], [a])
    session = get_db()
    session.execute(text("UPDATE cli_executions SET created_at = NOW() - INTERVAL 1 DAY WHERE id = :id"), {"id": stale})
    session.commit()

    assert service.get_execution(stale).status == service.STATUS_ABANDONED
    assert service.get_execution(stale).error
    assert service.get_execution(fresh).status == service.STATUS_PENDING


@pytest.mark.integration
def test_execution_pages_newest_first():
    a = _add_node("node-a")
    ids = [_create(["node", "list", str(i)], [a])[0] for i in range(3)]

    page, cursor = service.fetch_execution_page(None, 2)
    assert [e.id for e in page] == [ids[2], ids[1]]
    assert page[0].node_name == "node-a" and page[0].username == "unittest"
    assert cursor is not None

    page, cursor = service.fetch_execution_page(cursor, 2)
    assert [e.id for e in page] == [ids[0]]
    assert cursor is None


@pytest.mark.integration
def test_execution_page_rejects_a_cursor_of_another_listing():
    with pytest.raises(service.InvalidCursor):
        service.fetch_execution_page(service.encode_cursor(o="id", k=[1]), 2)


#
# dispatch
#

@pytest.mark.integration
def test_dispatch_asks_the_node_at_its_location(monkeypatch):
    a = _add_node("node-a", location="node-a.example:443")
    (execution_id,) = _create(["node", "list"], [a])
    calls = []
    monkeypatch.setattr(service.ace_api, "start_cli_execution",
                        lambda i, **kwargs: calls.append((i, kwargs["remote_host"])))

    service.dispatch_execution(execution_id)

    assert calls == [(execution_id, "node-a.example:443")]
    assert _row(execution_id).status == service.STATUS_PENDING


@pytest.mark.integration
def test_dispatch_translates_the_node_location(monkeypatch):
    a = _add_node("node-a", location="node-a")
    (execution_id,) = _create(["node", "list"], [a])
    monkeypatch.setitem(get_config().node_translation, "unittest", "node-a,node-a-http:443")
    calls = []
    monkeypatch.setattr(service.ace_api, "start_cli_execution",
                        lambda i, **kwargs: calls.append((i, kwargs["remote_host"])))

    service.dispatch_execution(execution_id)

    assert calls == [(execution_id, "node-a-http:443")]


@pytest.mark.integration
def test_dispatch_to_an_unreachable_node_fails_the_run(monkeypatch, caplog):
    a = _add_node("node-a", location="node-a.example:443")
    (execution_id,) = _create(["node", "list"], [a])

    def _refuse(*args, **kwargs):
        raise service.requests.ConnectionError("connection refused")

    monkeypatch.setattr(service.ace_api, "start_cli_execution", _refuse)
    service.dispatch_execution(execution_id)

    row = _row(execution_id)
    assert row.status == service.STATUS_FAILED
    assert "unable to reach node node-a at node-a.example:443" in row.error
    assert row.finished_at is not None
    assert f"starting cli execution {execution_id} on node node-a" in caplog.text


@pytest.mark.integration
def test_dispatch_refused_by_the_node_fails_the_run(monkeypatch, caplog):
    a = _add_node("node-a")
    (execution_id,) = _create(["node", "list"], [a])

    def _refuse(*args, **kwargs):
        response = service.requests.Response()
        response.status_code = 409
        response._content = b'{"detail":"not pending"}'
        raise service.requests.HTTPError("409", response=response)

    monkeypatch.setattr(service.ace_api, "start_cli_execution", _refuse)
    with caplog.at_level(logging.ERROR):
        service.dispatch_execution(execution_id)

    row = _row(execution_id)
    assert row.status == service.STATUS_FAILED
    assert "node node-a refused the run" in row.error and "not pending" in row.error
    assert f"starting cli execution {execution_id}" in caplog.text


@pytest.mark.integration
def test_dispatch_failure_keeps_a_run_the_node_already_claimed(monkeypatch):
    """The node may claim the row and then fail to answer; that run must not be failed."""
    local = _local_node()
    (execution_id,) = _create(["node", "list"], [local])

    def _claim_then_time_out(i, **kwargs):
        service.claim_execution(i)
        raise service.requests.ReadTimeout("read timed out")

    monkeypatch.setattr(service.ace_api, "start_cli_execution", _claim_then_time_out)
    service.dispatch_execution(execution_id)

    assert _row(execution_id).status == service.STATUS_RUNNING


#
# claim
#

@pytest.mark.integration
def test_claim_runs_a_row_once():
    (execution_id,) = _create(["node", "list"], [_local_node()], timeout_seconds=42)

    assert service.claim_execution(execution_id) == (["node", "list"], 42)
    row = _row(execution_id)
    assert row.status == service.STATUS_RUNNING and row.started_at is not None

    with pytest.raises(service.HTTPException) as e:
        service.claim_execution(execution_id)
    assert e.value.status_code == 409


@pytest.mark.integration
def test_claim_refuses_another_nodes_row():
    (execution_id,) = _create(["node", "list"], [_add_node("node-a")])
    with pytest.raises(service.HTTPException) as e:
        service.claim_execution(execution_id)
    assert e.value.status_code == 409
    assert "node-a" in e.value.detail
    assert _row(execution_id).status == service.STATUS_PENDING


@pytest.mark.integration
def test_claim_unknown_row():
    with pytest.raises(service.HTTPException) as e:
        service.claim_execution(999999999)
    assert e.value.status_code == 404


#
# the run
#

def _claimed(timeout_seconds: int = 60) -> int:
    (execution_id,) = _create(["placeholder"], [_local_node()], timeout_seconds=timeout_seconds)
    service.claim_execution(execution_id)
    return execution_id


def _python(monkeypatch, code: str):
    monkeypatch.setattr(service, "cli_command_line", lambda argv: [sys.executable, "-c", code])


@pytest.mark.integration
@pytest.mark.asyncio
async def test_run_records_output_and_exit_code(monkeypatch):
    execution_id = _claimed()
    _python(monkeypatch, "import sys; print('to stdout'); print('to stderr', file=sys.stderr); sys.exit(3)")

    await service.run_execution(execution_id, ["placeholder"], 60)

    row = _row(execution_id)
    assert row.status == service.STATUS_COMPLETED
    assert row.exit_code == 3
    assert "to stdout" in row.output and "to stderr" in row.output
    assert not row.output_truncated
    assert row.finished_at is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_run_that_exits_takes_what_it_started(monkeypatch):
    # issue 973: only a run the API stopped was ever cleaned up, and only within its session
    execution_id = _claimed()
    _python(monkeypatch, _ESCAPE)

    await asyncio.wait_for(service.run_execution(execution_id, ["placeholder"], 60), timeout=30)

    row = _row(execution_id)
    escaped = _escaped_pid(row.output)
    try:
        assert row.status == service.STATUS_COMPLETED
        assert row.exit_code == 0
        wait_for_condition(lambda: process_is_gone(escaped), timeout=10)
    finally:
        _kill(escaped)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_run_the_real_cli(monkeypatch):
    """The command really goes through the `ace` entry point."""
    execution_id = _claimed()

    await service.run_execution(execution_id, ["--help"], 60)

    row = _row(execution_id)
    assert row.status == service.STATUS_COMPLETED
    assert row.exit_code == 0
    assert "Analysis Correlation Engine" in row.output


@pytest.mark.integration
@pytest.mark.asyncio
async def test_run_is_killed_at_its_timeout(monkeypatch):
    execution_id = _claimed(timeout_seconds=1)
    _python(monkeypatch, "import time; print('started', flush=True); time.sleep(60)")

    await asyncio.wait_for(service.run_execution(execution_id, ["placeholder"], 1), timeout=30)

    row = _row(execution_id)
    assert row.status == service.STATUS_TIMED_OUT
    assert row.exit_code is None
    assert "stopped after its timeout of 1 seconds" in row.error
    assert "started" in row.output


@pytest.mark.integration
@pytest.mark.asyncio
async def test_run_caps_its_output(monkeypatch):
    monkeypatch.setattr(service, "MAX_OUTPUT_BYTES", 1000)
    execution_id = _claimed()
    _python(monkeypatch, "import sys; sys.stdout.write('x' * 500000)")

    await service.run_execution(execution_id, ["placeholder"], 60)

    row = _row(execution_id)
    assert row.status == service.STATUS_COMPLETED
    assert row.exit_code == 0
    assert row.output == "x" * 1000
    assert row.output_truncated


@pytest.mark.integration
@pytest.mark.asyncio
async def test_run_shows_output_while_running(monkeypatch):
    monkeypatch.setattr(service, "OUTPUT_FLUSH_SECONDS", 0.1)
    execution_id = _claimed()
    seen = []
    record_output = service._record_output

    def _spy(i, output, truncated):
        seen.append(output)
        record_output(i, output, truncated)

    monkeypatch.setattr(service, "_record_output", _spy)
    _python(monkeypatch, "import time; print('first', flush=True); time.sleep(1); print('second', flush=True)")

    await service.run_execution(execution_id, ["placeholder"], 60)

    assert seen and "first" in seen[0] and "second" not in seen[0]
    assert "second" in _row(execution_id).output


@pytest.mark.integration
@pytest.mark.asyncio
async def test_run_that_cannot_start_fails(monkeypatch, caplog):
    execution_id = _claimed()
    monkeypatch.setattr(service, "supervised_command_line", lambda command, timeout: ["/nonexistent/launcher"])

    await service.run_execution(execution_id, ["placeholder"], 60)

    row = _row(execution_id)
    assert row.status == service.STATUS_FAILED
    assert "unable to start the command" in row.error
    assert f"starting cli execution {execution_id}" in caplog.text


@pytest.mark.integration
@pytest.mark.asyncio
async def test_run_cancelled_by_shutdown_is_abandoned_and_killed(monkeypatch, tmp_path):
    pid_file = tmp_path / "pid"
    execution_id = _claimed()
    _python(monkeypatch, f"import os, time; open({str(pid_file)!r}, 'w').write(str(os.getpid())); time.sleep(60)")

    with pytest.raises(TimeoutError):
        # wait_for cancels the run, as uvicorn does at the end of its graceful shutdown
        await asyncio.wait_for(service.run_execution(execution_id, ["placeholder"], 60), timeout=2)

    row = _row(execution_id)
    assert row.status == service.STATUS_ABANDONED
    assert "stopped while the command was running" in row.error

    pid = int(pid_file.read_text())
    # polled on the event loop rather than with wait_for_condition: the loop is what reaps the child
    for _ in range(100):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        await asyncio.sleep(0.05)
    else:
        pytest.fail(f"child {pid} is still running")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_run_that_closes_its_output_but_keeps_running_times_out(monkeypatch):
    execution_id = _claimed(timeout_seconds=1)
    _python(monkeypatch, "import os, time; os.close(1); os.close(2); time.sleep(60)")

    await asyncio.wait_for(service.run_execution(execution_id, ["placeholder"], 1), timeout=30)

    assert _row(execution_id).status == service.STATUS_TIMED_OUT


@pytest.mark.integration
@pytest.mark.asyncio
async def test_run_internal_error_fails_the_run(monkeypatch, caplog):
    monkeypatch.setattr(service, "OUTPUT_FLUSH_SECONDS", 0.1)
    execution_id = _claimed()

    def _broken(*args):
        raise RuntimeError("database went away")

    monkeypatch.setattr(service, "_record_output", _broken)
    _python(monkeypatch, "import time; print('first', flush=True); time.sleep(60)")

    await asyncio.wait_for(service.run_execution(execution_id, ["placeholder"], 60), timeout=30)

    row = _row(execution_id)
    assert row.status == service.STATUS_FAILED
    assert "internal error running the command: database went away" in row.error
    assert f"running cli execution {execution_id}" in caplog.text


@pytest.mark.integration
@pytest.mark.asyncio
async def test_run_that_cannot_record_its_end_logs_it(monkeypatch, caplog):
    execution_id = _claimed()

    def _broken(*args, **kwargs):
        raise RuntimeError("database went away")

    monkeypatch.setattr(service, "_finish", _broken)
    _python(monkeypatch, "print('done')")

    await service.run_execution(execution_id, ["placeholder"], 60)

    assert f"recording the end of cli execution {execution_id}" in caplog.text
    assert _row(execution_id).status == service.STATUS_RUNNING


@pytest.mark.integration
def test_dispatch_unexpected_error_fails_the_run(monkeypatch, caplog):
    a = _add_node("node-a")
    (execution_id,) = _create(["node", "list"], [a])

    def _broken(*args, **kwargs):
        raise ValueError("bad location")

    monkeypatch.setattr(service.ace_api, "start_cli_execution", _broken)
    with caplog.at_level(logging.ERROR):
        service.dispatch_execution(execution_id)

    assert _row(execution_id).status == service.STATUS_FAILED
    assert "bad location" in _row(execution_id).error
    assert f"starting cli execution {execution_id}" in caplog.text


@pytest.mark.unit
def test_ace_api_start_cli_execution(monkeypatch):
    calls = []

    class _Response:
        def json(self):
            return {"id": 7, "status": "running"}

    def _call(command, **kwargs):
        calls.append((command, kwargs))
        return _Response()

    monkeypatch.setattr(service.ace_api, "_execute_api_call", _call)
    assert service.ace_api.start_cli_execution(7, remote_host="node-a:443") == {"id": 7, "status": "running"}
    assert calls == [("v2/engine/cli/7", {"method": service.ace_api.METHOD_POST, "remote_host": "node-a:443"})]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_timed_out_run_gets_sigterm_first(monkeypatch):
    """SIGTERM lets the command run its own shutdown (an engine releases its locks)."""
    execution_id = _claimed(timeout_seconds=1)
    _python(monkeypatch,
            "import signal, sys, time\n"
            "def _term(*args):\n"
            "    print('shutting down cleanly', flush=True)\n"
            "    sys.exit(0)\n"
            "signal.signal(signal.SIGTERM, _term)\n"
            "print('started', flush=True)\n"
            "time.sleep(60)\n")

    await asyncio.wait_for(service.run_execution(execution_id, ["placeholder"], 1), timeout=30)

    row = _row(execution_id)
    assert row.status == service.STATUS_TIMED_OUT
    assert "shutting down cleanly" in row.output


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_run_that_ignores_sigterm_is_killed(monkeypatch, caplog):
    monkeypatch.setattr(service, "TERM_GRACE_SECONDS", 1)
    execution_id = _claimed(timeout_seconds=1)
    _python(monkeypatch,
            "import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "print('started', flush=True)\n"
            "time.sleep(60)\n")

    with caplog.at_level(logging.WARNING):
        await asyncio.wait_for(service.run_execution(execution_id, ["placeholder"], 1), timeout=30)

    row = _row(execution_id)
    assert row.status == service.STATUS_TIMED_OUT
    assert "did not stop within 1 seconds of SIGTERM" in row.output
    # an engine killed this way kept its locks: the node's log says so, not only the run's output
    [record] = [r for r in caplog.records if "killed" in r.getMessage()]
    assert record.levelno == logging.WARNING
    assert record.cli_execution_id == execution_id


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_killed_run_takes_the_process_groups_its_children_moved_to(monkeypatch):
    # an engine's workers lead process groups of their own, which a SIGTERM of the command's group misses
    monkeypatch.setattr(service, "TERM_GRACE_SECONDS", 1)
    execution_id = _claimed(timeout_seconds=1)
    _python(monkeypatch,
            "import signal, subprocess, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "worker = subprocess.Popen(['sleep', '60'], process_group=0)\n"
            "print('worker', worker.pid, flush=True)\n"
            "time.sleep(60)\n")

    await asyncio.wait_for(service.run_execution(execution_id, ["placeholder"], 1), timeout=30)

    worker = int(_row(execution_id).output.split("worker ")[1].split()[0])
    try:
        wait_for_condition(lambda: process_is_gone(worker), timeout=10)
    finally:
        _kill(worker)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_run_that_stops_still_takes_what_it_started(monkeypatch, caplog):
    # an engine its shutdown watchdog ends has not stopped its workers, which lead groups of their own,
    # and a process may have left the session altogether
    execution_id = _claimed(timeout_seconds=1)
    _python(monkeypatch,
            _ESCAPE +
            "import subprocess, time\n"
            "worker = subprocess.Popen(['sleep', '60'], process_group=0, stdout=subprocess.DEVNULL)\n"
            "print('worker', worker.pid, flush=True)\n"
            "time.sleep(60)\n")

    with caplog.at_level(logging.WARNING):
        await asyncio.wait_for(service.run_execution(execution_id, ["placeholder"], 1), timeout=30)

    row = _row(execution_id)
    worker = int(row.output.split("worker ")[1].split()[0])
    escaped = _escaped_pid(row.output)
    try:
        assert row.status == service.STATUS_TIMED_OUT
        assert "did not stop within" not in row.output
        assert "killed 2 processes the command left running" in row.output
        [record] = [r for r in caplog.records if "killed" in r.getMessage()]
        assert record.cli_execution_id == execution_id
        wait_for_condition(lambda: process_is_gone(worker) and process_is_gone(escaped), timeout=10)
    finally:
        _kill(worker)
        _kill(escaped)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_run_whose_command_exited_is_not_held_open_by_what_it_started(monkeypatch):
    # an engine whose controller died leaves workers that hold its stdout; the launcher kills them, so
    # the run ends when the command does instead of at its timeout
    execution_id = _claimed(timeout_seconds=60)
    _python(monkeypatch,
            "import subprocess\n"
            "worker = subprocess.Popen(['sleep', '60'], process_group=0)\n"
            "print('worker', worker.pid, flush=True)\n")

    await asyncio.wait_for(service.run_execution(execution_id, ["placeholder"], 60), timeout=30)

    row = _row(execution_id)
    worker = int(row.output.split("worker ")[1].split()[0])
    try:
        assert row.status == service.STATUS_COMPLETED
        assert row.exit_code == 0
        assert process_is_gone(worker)
    finally:
        _kill(worker)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_run_that_writes_while_it_stops_is_not_blocked_on_its_output(monkeypatch, caplog):
    # an engine logging its shutdown to the console writes more than the pipe holds; unread, it blocks
    # and is killed at the grace, and so does the launcher's own message after it
    monkeypatch.setattr(service, "TERM_GRACE_SECONDS", 3)
    monkeypatch.setattr(service, "LAUNCHER_STOP_SECONDS", 2)
    execution_id = _claimed(timeout_seconds=1)
    _python(monkeypatch,
            "import signal, sys, time\n"
            "def _term(*args):\n"
            "    sys.stdout.write('x' * 1000000 + '\\nstopped cleanly\\n')\n"
            "    sys.exit(0)\n"
            "signal.signal(signal.SIGTERM, _term)\n"
            "print('started', flush=True)\n"
            "time.sleep(60)\n")

    with caplog.at_level(logging.WARNING):
        await asyncio.wait_for(service.run_execution(execution_id, ["placeholder"], 1), timeout=30)

    row = _row(execution_id)
    assert row.status == service.STATUS_TIMED_OUT
    assert "did not stop within" not in row.output
    assert row.output.endswith("stopped cleanly\nsandbox: stopped\n")
    assert not [r for r in caplog.records if r.name == service.logger.name and r.levelno >= logging.WARNING]


@pytest.mark.unit
def test_a_service_stopped_here_gets_its_whole_shutdown():
    # SIGTERM reaches only the command's group, so a service stops the rest itself, and its watchdog ends it
    # at its deadline plus WATCHDOG_GRACE: the session SIGKILL must not come first
    deadlines = [value.get("shutdown_deadline_seconds", DEFAULT_SHUTDOWN_DEADLINE)
                 for key, value in get_config().raw._data.items()
                 if key.startswith("service_") and isinstance(value, dict)]
    assert service.TERM_GRACE_SECONDS > max(deadlines) + WATCHDOG_GRACE
    # and a run still being stopped is not taken for one nothing watches
    assert service.STALE_GRACE_SECONDS > (service.TERM_GRACE_SECONDS + service.LAUNCHER_STOP_SECONDS
                                          + service.KILL_WAIT_SECONDS + service.OUTPUT_FLUSH_SECONDS)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_stopping_a_child_that_already_exited_does_nothing():
    process = await asyncio.create_subprocess_exec(sys.executable, "-c", "pass", start_new_session=True)
    await process.wait()

    await service._stop(1, process, lambda chunk: None)


@pytest.mark.integration
def test_a_node_runs_only_so_many_at_once(monkeypatch, caplog):
    monkeypatch.setattr(service, "MAX_RUNNING_PER_NODE", 2)
    local = _local_node()
    first, second, third = (_create(["node", "list"], [local])[0] for _ in range(3))
    service.claim_execution(first)
    service.claim_execution(second)

    with caplog.at_level(logging.INFO):
        with pytest.raises(service.HTTPException) as e:
            service.claim_execution(third)

    assert e.value.status_code == 429
    assert "2 cli executions are already running" in e.value.detail
    assert _row(third).status == service.STATUS_PENDING
    assert f"refused cli execution {third}" in caplog.text

    # once one finishes, the next can run
    service._finish(first, service.STATUS_COMPLETED, exit_code=0)
    service.claim_execution(third)
    assert _row(third).status == service.STATUS_RUNNING


@pytest.mark.integration
def test_deleting_the_user_keeps_their_runs():
    session = get_db()
    user = User(username="leaver", email="leaver@localhost", display_name="leaver", password="pw")
    session.add(user)
    session.commit()
    (execution_id,) = service.create_executions(user.id, "leaver", ["node", "list"], [_add_node("node-a")], 60)

    session.execute(text("DELETE FROM users WHERE id = :id"), {"id": user.id})
    session.commit()

    execution = service.get_execution(execution_id)
    assert execution is not None
    assert execution.user_id is None
    assert execution.username == "leaver"
    page, _ = service.fetch_execution_page(None, 10)
    assert execution_id in [e.id for e in page]


@pytest.mark.integration
def test_the_abandoned_warning_names_the_runs_and_nodes(caplog):
    (execution_id,) = _create(["node", "list"], [_add_node("node-a")])
    session = get_db()
    session.execute(text("UPDATE cli_executions SET created_at = NOW() - INTERVAL 1 DAY WHERE id = :id"), {"id": execution_id})
    session.commit()

    with caplog.at_level(logging.WARNING):
        assert service.expire_stale_executions() == 1

    record = next(r for r in caplog.records if "abandoned" in r.getMessage())
    assert record.cli_execution_ids == [execution_id]
    assert record.nodes == ["node-a"]
    # nothing left to expire
    assert service.expire_stale_executions() == 0


@pytest.mark.integration
def test_dispatch_to_a_busy_node_fails_the_run_without_an_error_report(monkeypatch, caplog):
    a = _add_node("node-a")
    (execution_id,) = _create(["node", "list"], [a])
    reported = []
    monkeypatch.setattr(service, "log_loop_exception", lambda *args, **kwargs: reported.append(args))

    def _busy(*args, **kwargs):
        response = service.requests.Response()
        response.status_code = 429
        response._content = b'{"detail":"3 cli executions are already running on node-a"}'
        raise service.requests.HTTPError("429", response=response)

    monkeypatch.setattr(service.ace_api, "start_cli_execution", _busy)
    with caplog.at_level(logging.INFO):
        service.dispatch_execution(execution_id)

    row = _row(execution_id)
    assert row.status == service.STATUS_FAILED
    assert "already running" in row.error
    assert reported == []
    assert "node busy" in caplog.text


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_launcher_that_does_not_stop_is_killed(monkeypatch, caplog):
    """The launcher bounds itself; if it hangs anyway, the API kills it, says so at ERROR, and the drain
    gives up on what the command left holding the pipe instead of waiting for it."""
    monkeypatch.setattr(service, "OUTPUT_FLUSH_SECONDS", 0.2)
    monkeypatch.setattr(service, "TERM_GRACE_SECONDS", 0.5)
    monkeypatch.setattr(service, "LAUNCHER_STOP_SECONDS", 0.5)
    # a stand-in launcher that ignores SIGTERM and contains nothing
    monkeypatch.setattr(service, "supervised_command_line", lambda command, timeout: command)
    execution_id = _claimed(timeout_seconds=1)
    _python(monkeypatch,
            "import signal, subprocess, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "p = subprocess.Popen(['sleep', '30'], start_new_session=True)\n"
            "print('holder', p.pid, flush=True)\n"
            "time.sleep(60)\n")

    try:
        with caplog.at_level(logging.ERROR):
            await asyncio.wait_for(service.run_execution(execution_id, ["placeholder"], 1), timeout=20)
        assert _row(execution_id).status == service.STATUS_TIMED_OUT
        [record] = [r for r in caplog.records if "did not exit" in r.getMessage()]
        assert record.levelno == logging.ERROR
        assert record.exc_info is not None  # what makes ErrorReportHandler write the error report
        assert record.cli_execution_id == execution_id
    finally:
        _kill(int(_row(execution_id).output.split()[1]))


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_failure_while_stopping_is_logged(monkeypatch, caplog):
    monkeypatch.setattr(service, "OUTPUT_FLUSH_SECONDS", 0.1)
    execution_id = _claimed()
    stop = service._stop

    def _broken_record(*args):
        raise RuntimeError("database went away")

    async def _broken_stop(i, process, append):
        await stop(i, process, append)  # still stop the child, then fail
        raise RuntimeError("stop failed")

    monkeypatch.setattr(service, "_record_output", _broken_record)
    monkeypatch.setattr(service, "_stop", _broken_stop)
    _python(monkeypatch, "import time; print('first', flush=True); time.sleep(60)")

    await asyncio.wait_for(service.run_execution(execution_id, ["placeholder"], 60), timeout=30)

    assert _row(execution_id).status == service.STATUS_FAILED
    assert f"stopping cli execution {execution_id}" in caplog.text
