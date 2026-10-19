"""The unit test log capture (tests/saq/helpers.py::MemoryLogHandler) across a fork."""

import logging
import os

import pytest

from saq.environment import ACE_MP_CONTEXT
from tests.saq.helpers import log_count, wait_for_log_count

# an os.register_at_fork child handler cannot be unregistered, so this one is registered once
# at import and does nothing unless a test turns it on
_log_inside_fork = False


def _at_fork_child():
    if _log_inside_fork:
        logging.info("record from inside the fork window")


os.register_at_fork(after_in_child=_at_fork_child)


def _child_logs():
    logging.info("record from the forked child")


@pytest.mark.integration
def test_record_from_inside_fork_is_dropped_and_capture_keeps_working():
    """A record logged by an at-fork child handler runs before multiprocessing gives the child
    its own Manager connection. Written over the parent's connection it would take the
    parent's reply and hang both processes; it has to be dropped instead, and records from
    the child after that point still arrive."""
    global _log_inside_fork
    _log_inside_fork = True
    try:
        process = ACE_MP_CONTEXT.Process(target=_child_logs)
        process.start()
    finally:
        _log_inside_fork = False

    try:
        process.join(30)
        assert not process.is_alive(), "the forked child hung writing a log record"
        assert process.exitcode == 0
    finally:
        if process.is_alive():
            process.kill()
            process.join(5)

    wait_for_log_count("record from the forked child", 1)
    assert log_count("record from inside the fork window") == 0

    # the parent's connection to the Manager is still in step
    logging.info("record from the parent after the fork")
    assert log_count("record from the parent after the fork") == 1
