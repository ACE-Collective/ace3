"""Fork safety for the SQLAlchemy side of the connection pool.

ACE forks constantly -- the engine controller, every worker, the collectors -- and
ACE_MP_CONTEXT is the ``fork`` context, so a child starts life holding the parent's
open MySQL sockets. Two processes reading and writing one TLS-wrapped socket
desynchronises the record layer, and the *parent* is usually the one that notices, with
``[SSL: RECORD_LAYER_FAILURE] ... Lost connection to MySQL server during query``.
"""

import logging
import os

import pytest

from sqlalchemy import text

from saq.database.pool import get_db, reset_database_after_fork
from saq.environment import ACE_MP_CONTEXT


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
    # prevents it: the child hook emits nothing through logging at all.
    read_fd, write_fd = os.pipe()
    parent_pid = os.getpid()

    class ForkProbe(logging.Handler):
        def emit(self, record):
            if os.getpid() != parent_pid:
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


@pytest.mark.integration
def test_reset_database_after_fork_writes_to_stderr(capsys):
    # calling this in the parent is benign: no tracked connection has a foreign pid, so
    # nothing is force closed, and dispose(close=False) plus registry.clear() only swap in
    # fresh pools that SQLAlchemy rebuilds lazily.
    reset_database_after_fork()
    assert "inherited database connections" in capsys.readouterr().err
