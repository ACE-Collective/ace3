"""The yara scanner server, running for real against rules written by each test."""

import multiprocessing
import os
import shutil
import signal
import socket
import tempfile
import time
import uuid

import psutil
import pytest

from saq.signatures.builtin import SIGNATURE_VERSION_UNKNOWN
from saq.util.hashing import sha256_file
from saq.yara_scanning import client, protocol
from saq.yara_scanning.client import YaraServiceUnavailable
from saq.yara_scanning.qa import RECORDER_NICENESS
from saq.yara_scanning.server import ScannerSettings, YaraScannerServer, _fork
from tests.saq.helpers import wait_for_condition
from tests.saq.yara_qa.conftest import QA_UUID, counter_row, match_rows

RULE_A = """
rule rule_a {
    strings:
        $a = "MATCH_A"
    condition:
        $a
}
"""

RULE_BINARY = """
rule rule_binary {
    strings:
        $b = { 00 FF 00 FF }
    condition:
        $b
}
"""

RULE_TAGGED = """
rule rule_tagged {
    meta:
        meta_tags = "email_attachment"
    strings:
        $a = "MATCH_A"
    condition:
        $a
}
"""

RULE_B = """
rule rule_b {
    strings:
        $b = "MATCH_B"
    condition:
        $b
}
"""


RULE_QA = f"""
rule rule_qa {{
    meta:
        modifiers = "qa"
        uuid = "{QA_UUID}"
    strings:
        $a = "MATCH_A"
    condition:
        $a
}}
"""


def _write(path, content: str):
    with open(path, "w") as fp:
        fp.write(content)

    # the rule tracking compares modification times; make sure a rewrite is seen as one
    stamp = time.time() + 2
    os.utime(path, (stamp, stamp))


@pytest.fixture
def signature_dir(tmp_path) -> str:
    result = tmp_path / "signatures"
    (result / "rules").mkdir(parents=True)
    return str(result)


@pytest.fixture
def rules_dir(signature_dir) -> str:
    return os.path.join(signature_dir, "rules")


@pytest.fixture
def target(tmp_path) -> str:
    result = str(tmp_path / "target.txt")
    _write(result, "some text MATCH_A MATCH_B some more text")
    return result


@pytest.fixture
def socket_dir():
    # AF_UNIX paths are limited to 108 bytes, which a tmp_path under xdist can come close to
    result = tempfile.mkdtemp(prefix="yss-")
    yield result
    shutil.rmtree(result, ignore_errors=True)


@pytest.fixture
def qa_spool(tmp_path) -> str:
    return str(tmp_path / "qa_spool")


@pytest.fixture
def make_server(socket_dir, signature_dir):
    servers = []

    def _make(**overrides) -> YaraScannerServer:
        settings = ScannerSettings(**{
            "socket_dir": socket_dir,
            "signature_dir": signature_dir,
            "git_repo_dirs": (),
            "worker_count": 2,
            "update_frequency": 1,
            "default_timeout": 5,
            "compile_timeout": 60,
            "io_timeout": 5,
            "max_data_bytes": 1024 * 1024,
            "max_requests_per_worker": 0,
            "backlog": 50,
            **overrides})

        server = YaraScannerServer(settings)
        servers.append(server)
        server.start()
        return server

    yield _make

    for server in servers:
        server.stop()


def _socket_path(server: YaraScannerServer) -> str:
    return server.settings.socket_path


def _scan(server: YaraScannerServer, path: str, **kwargs) -> list[dict]:
    return client.scan_file(path, socket_path=_socket_path(server), **kwargs)


def _rules(matches: list[dict]) -> set[str]:
    return {match["rule"] for match in matches}


def _is_recorder(process: psutil.Process) -> bool:
    # the only process of the tree that lowers its priority
    try:
        return process.nice() == RECORDER_NICENESS
    except psutil.Error:
        return False


def _generations(server: YaraScannerServer) -> list[psutil.Process]:
    return [_ for _ in psutil.Process(server.process.pid).children() if not _is_recorder(_)]


def _recorders(server: YaraScannerServer) -> list[psutil.Process]:
    return [_ for _ in psutil.Process(server.process.pid).children()
            if _is_recorder(_) and _.status() != psutil.STATUS_ZOMBIE]


def _qa_context(path: str) -> dict:
    return {"root_uuid": str(uuid.uuid4()), "observable_uuid": str(uuid.uuid4()), "file_name": os.path.basename(path),
            "file_size": os.path.getsize(path), "sha256": sha256_file(path)}


def _workers(server: YaraScannerServer) -> list[psutil.Process]:
    result = []
    for generation in _generations(server):
        result.extend(generation.children())

    return result


def _process_group(pgid: int) -> list[int]:
    result = []
    for process in psutil.process_iter():
        try:
            if os.getpgid(process.pid) == pgid and process.status() != psutil.STATUS_ZOMBIE:
                result.append(process.pid)
        except (ProcessLookupError, psutil.Error):
            pass

    return result


@pytest.mark.integration
def test_scan_file(make_server, rules_dir, target):
    _write(os.path.join(rules_dir, "a.yar"), RULE_A)
    server = make_server()
    assert server.wait_for_start(30)

    matches = _scan(server, target)
    assert _rules(matches) == {"rule_a"}
    match = matches[0]
    assert match["target"] == target
    assert match["namespace"] == rules_dir
    assert match["commit"] is None
    assert match["strings"] == [(10, "$a", b"MATCH_A")]


@pytest.mark.integration
def test_scan_binary_data(make_server, rules_dir):
    _write(os.path.join(rules_dir, "binary.yar"), RULE_BINARY)
    server = make_server()
    assert server.wait_for_start(30)

    matches = client.scan_data(b"\xfe\x00\xff\x00\xff\xfe", socket_path=_socket_path(server))
    assert _rules(matches) == {"rule_binary"}
    assert matches[0]["strings"] == [(1, "$b", b"\x00\xff\x00\xff")]

    assert client.scan_data(b"\x00\x00", socket_path=_socket_path(server)) == []


@pytest.mark.integration
def test_meta_tags_filter_rules(make_server, rules_dir, target):
    _write(os.path.join(rules_dir, "tagged.yar"), RULE_TAGGED)
    server = make_server()
    assert server.wait_for_start(30)

    assert _scan(server, target) == []
    assert _rules(_scan(server, target, meta_tags=["email_attachment"])) == {"rule_tagged"}


@pytest.mark.integration
def test_missing_file_is_a_scan_error(make_server, rules_dir, tmp_path):
    _write(os.path.join(rules_dir, "a.yar"), RULE_A)
    server = make_server()
    assert server.wait_for_start(30)

    with pytest.raises(client.YaraScanError):
        _scan(server, str(tmp_path / "does_not_exist"))


@pytest.mark.integration
def test_bad_request(make_server, rules_dir):
    _write(os.path.join(rules_dir, "a.yar"), RULE_A)
    server = make_server()
    assert server.wait_for_start(30)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(_socket_path(server))
        assert protocol.recv_exact(sock, 1) == protocol.ACK
        protocol.send_json(sock, {"v": 99, "op": protocol.OP_SCAN_FILE, "path": "/etc/hostname"})
        assert protocol.recv_json(sock, 1024 * 1024)["status"] == protocol.STATUS_BAD_REQUEST

    # the worker is still serving
    assert client.scan_data(b"nothing", socket_path=_socket_path(server)) == []


@pytest.mark.integration
def test_concurrent_clients_use_every_worker(make_server, rules_dir, target):
    """Clients are spread over the workers by the kernel: a client holding one worker does not
    stop another client from being served."""
    _write(os.path.join(rules_dir, "a.yar"), RULE_A)
    server = make_server(worker_count=2)
    assert server.wait_for_start(30)

    # hold one worker by connecting and never sending the request
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stalled:
        stalled.settimeout(10)
        stalled.connect(_socket_path(server))
        assert protocol.recv_exact(stalled, 1) == protocol.ACK

        start = time.monotonic()
        assert _rules(_scan(server, target)) == {"rule_a"}
        assert time.monotonic() - start < 2


@pytest.mark.integration
def test_hot_reload_without_downtime(make_server, rules_dir, target):
    _write(os.path.join(rules_dir, "a.yar"), RULE_A)
    server = make_server()
    assert server.wait_for_start(30)
    first_generation = {process.pid for process in _generations(server)}

    _write(os.path.join(rules_dir, "b.yar"), RULE_B)

    # every scan made while the generations change over is served
    seen = []

    def _reloaded() -> bool:
        rules = _rules(_scan(server, target))
        seen.append(rules)
        return rules == {"rule_a", "rule_b"}

    wait_for_condition(_reloaded, timeout=30, delay=0.05)
    assert all(rules in ({"rule_a"}, {"rule_a", "rule_b"}) for rules in seen)

    # the previous generation retires as soon as its idle workers stop (well inside drain_timeout,
    # which is what a worker kept alive by a stray copy of its control pipe would take)
    wait_for_condition(lambda: len(_generations(server)) == 1, timeout=3)
    assert not first_generation & {process.pid for process in _generations(server)}


@pytest.mark.integration
def test_rules_that_do_not_compile_keep_the_previous_rules(make_server, rules_dir, target):
    _write(os.path.join(rules_dir, "a.yar"), RULE_A)
    server = make_server()
    assert server.wait_for_start(30)
    serving = {process.pid for process in _generations(server)}

    # each file compiles on its own, but a rule name used twice in one namespace does not
    # compile combined, so no rules can be loaded from the directory at all
    _write(os.path.join(rules_dir, "duplicate.yar"), RULE_A)

    # the failed generation comes and goes, and is not retried while the rules stay the same
    time.sleep(5)
    assert {process.pid for process in _generations(server)} == serving
    assert _rules(_scan(server, target)) == {"rule_a"}

    # fixing the rules starts a generation that replaces the old one
    os.remove(os.path.join(rules_dir, "duplicate.yar"))
    _write(os.path.join(rules_dir, "b.yar"), RULE_B)
    wait_for_condition(lambda: _rules(_scan(server, target)) == {"rule_a", "rule_b"}, timeout=30)


@pytest.mark.integration
def test_no_rules_at_start(make_server, rules_dir, target):
    """Nothing serves until rules can be loaded, and clients are told so at once."""
    server = make_server()
    assert not server.wait_for_start(3)
    assert not os.path.lexists(_socket_path(server))

    with pytest.raises(YaraServiceUnavailable):
        _scan(server, target)

    _write(os.path.join(rules_dir, "a.yar"), RULE_A)
    assert server.wait_for_start(30)
    assert _rules(_scan(server, target)) == {"rule_a"}


@pytest.mark.integration
def test_dead_worker_is_replaced(make_server, rules_dir, target):
    _write(os.path.join(rules_dir, "a.yar"), RULE_A)
    server = make_server(worker_count=1)
    assert server.wait_for_start(30)

    (worker,) = _workers(server)
    os.kill(worker.pid, signal.SIGKILL)

    wait_for_condition(lambda: [_.pid for _ in _workers(server)] not in ([], [worker.pid]), timeout=10)
    assert _rules(_scan(server, target)) == {"rule_a"}


@pytest.mark.integration
def test_dead_generation_is_replaced(make_server, rules_dir, target):
    _write(os.path.join(rules_dir, "a.yar"), RULE_A)
    server = make_server()
    assert server.wait_for_start(30)

    (generation,) = _generations(server)
    workers = generation.children()
    os.kill(generation.pid, signal.SIGKILL)

    # its workers see their control pipe close and exit
    psutil.wait_procs(workers, timeout=10)
    assert not any(worker.is_running() and worker.status() != psutil.STATUS_ZOMBIE for worker in workers)

    wait_for_condition(lambda: _rules(_scan(server, target)) == {"rule_a"}, timeout=30)


@pytest.mark.integration
def test_workers_are_recycled(make_server, rules_dir, target):
    _write(os.path.join(rules_dir, "a.yar"), RULE_A)
    server = make_server(worker_count=1, max_requests_per_worker=2)
    assert server.wait_for_start(30)

    (worker,) = _workers(server)
    for _ in range(2):
        assert _rules(_scan(server, target)) == {"rule_a"}

    wait_for_condition(lambda: [_.pid for _ in _workers(server)] not in ([], [worker.pid]), timeout=10)
    assert _rules(_scan(server, target)) == {"rule_a"}


@pytest.mark.integration
def test_stop_leaves_nothing_behind(make_server, rules_dir, socket_dir):
    _write(os.path.join(rules_dir, "a.yar"), RULE_A)
    server = make_server()
    assert server.wait_for_start(30)
    pgid = server.process.pid
    assert len(_process_group(pgid)) == 1 + 1 + 2  # manager, generation, workers

    start = time.monotonic()
    server.stop()
    assert time.monotonic() - start < server.settings.drain_timeout + 3

    assert server.wait(0)
    assert _process_group(pgid) == []
    assert os.listdir(socket_dir) == []


@pytest.mark.integration
def test_manager_stops_when_the_service_dies(make_server, rules_dir):
    """The manager watches the control pipe the service holds, so it stops if the service is gone."""
    _write(os.path.join(rules_dir, "a.yar"), RULE_A)
    server = make_server()
    assert server.wait_for_start(30)

    # what the service process dying does to the pipe
    os.close(server.ctl_w)
    server.ctl_w = None

    assert server.wait(server.settings.drain_timeout + 3)


@pytest.mark.unit
def test_forked_children_get_their_own_manager_connections():
    """The test suite's log handler is a multiprocessing Manager list. Children forked by the server
    must not share their parent's connection to it, or concurrent log calls hang."""
    manager = multiprocessing.Manager()
    try:
        records = manager.list()
        records.append("parent")  # the parent now has a connection a child would inherit

        def _append() -> int:
            for i in range(200):
                records.append((os.getpid(), i))

            return 0

        for _ in range(5):
            pids = [_fork([], _append) for _ in range(4)]
            deadline = time.monotonic() + 30
            for pid in pids:
                while not os.waitpid(pid, os.WNOHANG)[0]:
                    if time.monotonic() > deadline:
                        os.kill(pid, signal.SIGKILL)
                        os.waitpid(pid, 0)
                        pytest.fail("a forked child hung talking to the multiprocessing manager")

                    time.sleep(0.01)

        assert len(records) == 1 + 5 * 4 * 200
    finally:
        manager.shutdown()


@pytest.mark.integration
def test_qa_matches_are_recorded_after_the_answer(make_server, rules_dir, target, qa_spool):
    _write(os.path.join(rules_dir, "qa.yar"), RULE_QA)
    # one worker: it writes the job of a scan before it takes the next one
    server = make_server(worker_count=1, qa_spool_dir=qa_spool)
    assert server.wait_for_start(30)
    assert len(_recorders(server)) == 1

    # without the origin of the file, the match is only answered
    assert _rules(_scan(server, target)) == {"rule_qa"}

    qa_context = _qa_context(target)
    assert _rules(_scan(server, target, qa=qa_context)) == {"rule_qa"}

    wait_for_condition(lambda: len(match_rows()) == 1, timeout=30)
    (row,) = match_rows()
    assert row.sha256 == qa_context["sha256"]
    assert (row.root_uuid, row.observable_uuid) == (qa_context["root_uuid"], qa_context["observable_uuid"])
    assert counter_row(SIGNATURE_VERSION_UNKNOWN).match_count == 1

    wait_for_condition(lambda: os.listdir(qa_spool) == [], timeout=10)


@pytest.mark.integration
def test_dead_recorder_is_replaced(make_server, rules_dir, target, qa_spool):
    _write(os.path.join(rules_dir, "qa.yar"), RULE_QA)
    server = make_server(qa_spool_dir=qa_spool)
    assert server.wait_for_start(30)

    (recorder,) = _recorders(server)
    os.kill(recorder.pid, signal.SIGKILL)
    wait_for_condition(lambda: [_.pid for _ in _recorders(server)] not in ([], [recorder.pid]), timeout=10)

    # scanning never depended on it, and what was spooled meanwhile is recorded
    assert _rules(_scan(server, target, qa=_qa_context(target))) == {"rule_qa"}
    wait_for_condition(lambda: len(match_rows()) == 1, timeout=30)


@pytest.mark.integration
def test_stop_leaves_no_recorder_behind(make_server, rules_dir, qa_spool):
    _write(os.path.join(rules_dir, "a.yar"), RULE_A)
    server = make_server(qa_spool_dir=qa_spool)
    assert server.wait_for_start(30)
    pgid = server.process.pid
    assert len(_process_group(pgid)) == 1 + 1 + 1 + 2  # manager, recorder, generation, workers

    server.stop()
    assert server.wait(0)
    assert _process_group(pgid) == []
