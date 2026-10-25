"""A worker is forked with every object of the engine's process frozen, so that its collections don't copy the
pages it shares with that process; the engine's process unfreezes them again at once."""

import gc
import os
import select
import signal
from unittest.mock import Mock

import pytest

from saq.engine import worker as worker_module
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineType
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.worker import Worker


def _worker() -> Worker:
    return Worker(name="test_worker",
                  configuration_manager=ConfigurationManager(EngineConfiguration(engine_type=EngineType.LOCAL,
                                                                                 single_threaded_mode=True)),
                  node_manager=Mock(spec=NodeManagerInterface))


@pytest.mark.unit
def test_the_worker_keeps_what_it_inherited_frozen():
    read_fd, write_fd = os.pipe()
    worker = _worker()

    def worker_loop(execution_mode, pending_failure):
        os.write(write_fd, str(gc.get_freeze_count()).encode())

    worker.worker_loop = worker_loop
    try:
        worker.start()
        ready, _, _ = select.select([read_fd], [], [], 10)
        assert ready, "the worker never reported"
        assert int(os.read(read_fd, 64)) > 0
        assert gc.get_freeze_count() == 0
    finally:
        try:
            os.killpg(worker.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        worker.process.join(5)
        os.close(read_fd)
        os.close(write_fd)


@pytest.mark.unit
def test_a_fork_that_fails_leaves_nothing_frozen(monkeypatch):
    class FailingProcess:
        def __init__(self, **kwargs):
            pass

        def start(self):
            raise OSError("fork failed")

    monkeypatch.setattr(worker_module.ACE_MP_CONTEXT, "Process", FailingProcess)
    with pytest.raises(OSError):
        _worker().start()

    assert gc.get_freeze_count() == 0
