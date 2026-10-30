"""Fork safety for the SQLAlchemy side of the connection pool.

ACE forks constantly -- the engine controller, every worker, the collectors -- and
ACE_MP_CONTEXT is the ``fork`` context, so a child starts life holding the parent's
open MySQL sockets. Two processes reading and writing one TLS-wrapped socket
desynchronises the record layer, and the *parent* is usually the one that notices, with
``[SSL: RECORD_LAYER_FAILURE] ... Lost connection to MySQL server during query``.
"""

import gc
import io
import logging
import os
import signal
import socket
import sys
import threading

import pymysql
import pytest

from sqlalchemy import text
from sqlalchemy.pool.base import reset_none, reset_rollback

import saq
from saq.database import pool
from saq.database.pool import get_db, reset_database_after_fork
from saq.environment import ACE_MP_CONTEXT
from tests.saq.helpers import WaitTimedOutError, wait_for_condition


def _child_uses_the_database():
    """Runs in the forked child. Does exactly what any ACE child process does first."""
    get_db().execute(text("SELECT 1")).scalar()
    get_db().commit()


@pytest.mark.integration
def test_orm_connection_survives_fork():
    # leave the transaction open so the parent's session is holding a checked out
    # connection at the moment of the fork. this is the state Engine.start_nonblocking()
    # forks in, and the one the checkout pid guard cannot see: no checkout event fires in
    # the child because the connection is already checked out.
    assert get_db().execute(text("SELECT 1")).scalar() == 1

    process = ACE_MP_CONTEXT.Process(target=_child_uses_the_database)
    process.start()
    process.join(30)

    assert not process.is_alive()
    assert process.exitcode == 0

    # the child must not have disturbed the connection the parent still holds
    assert get_db().execute(text("SELECT 1")).scalar() == 1
    get_db().commit()


def _child_does_nothing():
    """Runs in the forked child. The at-fork hook is the only thing that gets to run."""
    pass


@pytest.mark.integration
def test_at_fork_child_hook_does_not_use_logging():
    # os.register_at_fork child handlers run inside os.fork(), before multiprocessing's
    # _bootstrap resets its fork-aware thread-locals. A root handler that talks to another
    # process would therefore be used over the connection the child inherited from the
    # parent -- and the unit test MemoryLogHandler is exactly that, writing every record
    # into a SyncManager list. Two processes on one stream socket desynchronise it and both
    # sides block forever, which wedges the whole suite.
    #
    # Rather than reproduce that deadlock (a hanging test wedges the session lock, which is
    # the thing we are trying to make cheap to diagnose), assert the invariant that
    # prevents it: ACE's child hooks emit nothing through logging at all. Only ACE's own
    # records count: a third-party package's hook (huggingface_hub closes its httpx client
    # in the child, and httpcore logs the close) is registered only once something has
    # imported it, is outside this repository's control, and is what
    # MemoryLogHandler.proxy_pid exists to survive (tests/saq/test_memory_log_handler.py).
    read_fd, write_fd = os.pipe()
    parent_pid = os.getpid()
    ace_source = os.path.dirname(saq.__file__) + os.sep

    class ForkProbe(logging.Handler):
        def emit(self, record):
            if os.getpid() != parent_pid and record.pathname.startswith(ace_source):
                os.write(write_fd, b"x")

    handler = ForkProbe()
    handler.setLevel(logging.DEBUG)
    root = logging.getLogger()
    root.addHandler(handler)

    try:
        process = ACE_MP_CONTEXT.Process(target=_child_does_nothing)
        process.start()
        process.join(30)
    finally:
        root.removeHandler(handler)
        # closing the parent's end is what turns the read below into an EOF rather than a
        # block: the child's inherited copy is gone once it exits.
        os.close(write_fd)

    assert not process.is_alive()

    emitted = os.read(read_fd, 4096)
    os.close(read_fd)
    assert emitted == b"", "the at-fork child hook emitted a log record"


def _child_collects_what_it_inherited():
    """Runs in the forked child. The inherited session's connection is in a reference cycle, so it goes back to
    the inherited pool here rather than in the at-fork hook."""
    gc.collect()


@pytest.mark.integration
def test_a_connection_checked_out_at_the_fork_is_dropped_in_the_child_without_an_error():
    # an open transaction holds a connection checked out at the fork, the state Engine.start_nonblocking() forks
    # in. returning it to the pool the child abandoned must not try to roll it back over the socket the hook took
    # away, which SQLAlchemy logs at ERROR as "Exception during reset or similar"
    assert get_db().execute(text("SELECT 1")).scalar() == 1

    read_fd, write_fd = os.pipe()
    parent_pid = os.getpid()

    class ForkProbe(logging.Handler):
        def emit(self, record):
            if os.getpid() != parent_pid and record.levelno >= logging.WARNING:
                os.write(write_fd, f"{record.name}: {record.getMessage()}\n".encode())

    handler = ForkProbe()
    root = logging.getLogger()
    root.addHandler(handler)

    try:
        process = ACE_MP_CONTEXT.Process(target=_child_collects_what_it_inherited)
        process.start()
        process.join(30)
    finally:
        root.removeHandler(handler)
        os.close(write_fd)

    assert not process.is_alive()
    assert process.exitcode == 0

    emitted = os.read(read_fd, 65536).decode()
    os.close(read_fd)
    assert "Exception during reset" not in emitted

    # the parent's connection is untouched
    assert get_db().execute(text("SELECT 1")).scalar() == 1
    get_db().commit()


@pytest.mark.integration
def test_only_the_abandoned_pool_stops_rolling_back(capfd):
    # recreate() copies reset_on_return into the pool that replaces the abandoned one, and a pool that never rolls
    # back hands the next checkout a connection still inside the last one's transaction
    engine = get_db().get_bind()
    inherited_pool = engine.pool
    assert inherited_pool._reset_on_return is reset_rollback

    reset_database_after_fork()

    assert engine.pool is not inherited_pool
    assert inherited_pool._reset_on_return is reset_none
    assert engine.pool._reset_on_return is reset_rollback


@pytest.mark.integration
def test_reset_database_after_fork_writes_to_stderr(capfd):
    # calling this in the parent is benign: no tracked connection has a foreign pid, so
    # nothing is closed, and dispose(close=False) plus registry.clear() only swap in
    # fresh pools that SQLAlchemy rebuilds lazily.
    reset_database_after_fork()
    assert "inherited database connections" in capfd.readouterr().err


class _Blocking(io.RawIOBase):
    """A raw stream whose reads and writes wait until released, so a thread reading or writing through
    a buffered stream over it holds that stream's lock for as long as the test needs."""

    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()

    def readable(self):
        return True

    def writable(self):
        return True

    def readinto(self, b):
        self.entered.set()
        self.release.wait(30)
        return 0

    def write(self, b):
        self.entered.set()
        self.release.wait(30)
        return len(b)


def _exit_status(pid: int) -> int:
    """The forked child's exit status. A child still there after 10 seconds is hung in the at-fork hook."""
    status = []

    def exited():
        done, code = os.waitpid(pid, os.WNOHANG)
        if done:
            status.append(code)
        return bool(done)

    try:
        wait_for_condition(exited, timeout=10)
    except WaitTimedOutError:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        pytest.fail("the forked child hung in the at-fork hook")

    return os.waitstatus_to_exitcode(status[0])


@pytest.mark.unit
def test_a_fork_while_a_thread_waits_for_a_query_reply_does_not_hang():
    # the engine's lock keepalive thread does this every few seconds: it holds the connection's read
    # buffer lock while it waits, and only the forking thread exists in the child
    ours, theirs = socket.socketpair()
    # pymysql reads through ours.makefile("rb"), which leaves the socket with an open reader of its own:
    # with one, ours.close() does not close the descriptor
    makefile = ours.makefile("rb")
    blocking = _Blocking()
    connection = pymysql.connect(defer_connect=True)
    connection._sock = ours
    connection._rfile = io.BufferedReader(blocking)
    pool._track_connection(connection)
    reader = threading.Thread(target=connection._rfile.read, args=(4,), daemon=True)
    reader.start()
    assert blocking.entered.wait(5)

    fd = ours.fileno()
    read_fd, write_fd = os.pipe()
    try:
        pid = os.fork()
        if pid == 0:
            # the hook has run: report whether it closed this process's copy of the socket
            try:
                os.fstat(fd)
                os.write(write_fd, b"open")
            except OSError:
                os.write(write_fd, b"closed")
            os._exit(0)

        assert _exit_status(pid) == 0
        assert os.read(read_fd, 16) == b"closed"
        # and left the parent's alone
        ours.sendall(b"ping")
        assert theirs.recv(4) == b"ping"
    finally:
        blocking.release.set()
        reader.join(5)
        with pool._tracked_connections_lock:
            pool._tracked_connections.discard(connection)
        connection._sock = connection._rfile = None
        for f in (read_fd, write_fd):
            os.close(f)
        makefile.close()
        ours.close()
        theirs.close()


class _Inherited:
    """Stands in for a pymysql connection a forked child inherited: opened under another pid."""

    def __init__(self, sock):
        self._ace_pid = -1
        self._sock = sock
        self._rfile = None


class _Broken:
    def __init__(self):
        self._ace_pid = -1

    @property
    def _sock(self):
        raise RuntimeError("no socket here")


@pytest.mark.unit
def test_reset_database_after_fork_drops_what_it_inherited_and_reports_what_it_could_not(monkeypatch, capfd):
    ours, theirs = socket.socketpair()
    fd = ours.fileno()
    inherited, broken = _Inherited(ours), _Broken()
    with pool._tracked_connections_lock:
        pool._tracked_connections.add(inherited)
        pool._tracked_connections.add(broken)

    def fail():
        raise RuntimeError("gone")

    monkeypatch.setattr(pool, "_abandoned_after_fork", [])
    monkeypatch.setattr(pool, "_db_engines", {type("Engine", (), {"pool": None, "dispose": lambda self, close: fail()})()})
    monkeypatch.setattr(pool, "_db_sessions", {"ace": type("Session", (), {"registry": type("Registry", (), {"clear": staticmethod(fail)})()})()})
    try:
        reset_database_after_fork()

        # this process's descriptor is closed and the connection looks force closed; the socket object is kept
        with pytest.raises(OSError):
            os.fstat(fd)
        assert inherited._sock is None and inherited._rfile is None
        assert pool._abandoned_after_fork == [(ours, None)]

        err = capfd.readouterr().err
        assert "unable to close inherited connection after fork: no socket here" in err
        assert "unable to dispose inherited engine after fork: gone" in err
        assert "unable to clear inherited ace session after fork: gone" in err
        assert "NOTICE: reset 2 inherited database connections" in err
    finally:
        with pool._tracked_connections_lock:
            pool._tracked_connections.discard(inherited)
            pool._tracked_connections.discard(broken)
        theirs.close()


@pytest.mark.unit
def test_a_diagnostic_that_cannot_be_written_is_dropped(monkeypatch):
    # a hung up terminal or a pipe nobody reads: raising here would end the hook before it finished
    def write(fd, data):
        raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr(pool.os, "write", write)
    pool._write_stderr("NOTICE: something\n")


@pytest.mark.unit
def test_a_fork_while_a_thread_writes_to_stderr_does_not_hang(monkeypatch):
    blocking = _Blocking()
    stderr = io.TextIOWrapper(io.BufferedWriter(blocking, buffer_size=8), write_through=True)
    monkeypatch.setattr(sys, "stderr", stderr)
    writer = threading.Thread(target=stderr.write, args=("x" * 64,), daemon=True)
    writer.start()
    assert blocking.entered.wait(5)

    try:
        pid = os.fork()
        if pid == 0:
            os._exit(0)  # the hook has run

        assert _exit_status(pid) == 0
    finally:
        blocking.release.set()
        writer.join(5)
