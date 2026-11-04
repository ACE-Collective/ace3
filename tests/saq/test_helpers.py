import os
import signal
import subprocess
import sys

import pytest

from saq.environment import get_base_dir
from tests.saq.helpers import WaitTimedOutError, process_is_gone, wait_for_condition

# a pytest process reduced to what matters here: it starts the log collector, reports the pid of
# the collector's server and then waits to be killed
_START_LOG_COLLECTOR = """
from tests.saq import helpers
helpers.initialize_unittest_logging()
print(helpers.test_log_manager._process.pid, flush=True)
import time
time.sleep(120)
"""


@pytest.mark.unit
def test_log_collector_exits_when_its_process_is_killed():
    # the OOM killer SIGKILLs a pytest worker, and no finalizer of the worker ever runs
    worker = subprocess.Popen(
        [sys.executable, "-c", _START_LOG_COLLECTOR],
        cwd=get_base_dir(),
        stdout=subprocess.PIPE,
        text=True,
    )
    server_pid = None
    try:
        server_pid = int(worker.stdout.readline())
        assert not process_is_gone(server_pid)
        os.kill(worker.pid, signal.SIGKILL)
        worker.wait(timeout=10)

        wait_for_condition(lambda: process_is_gone(server_pid), timeout=10)
    except WaitTimedOutError:
        pytest.fail(f"the log collector's server (pid {server_pid}) outlived the process that started it")
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.wait(timeout=10)
        if server_pid is not None and not process_is_gone(server_pid):
            os.kill(server_pid, signal.SIGKILL)


@pytest.mark.unit
def test_exit_with_a_process_that_already_exited():
    exited = subprocess.Popen([sys.executable, "-c", "pass"])
    exited.wait(timeout=10)

    # a pid nothing has right now: the process was reaped above
    result = subprocess.run(
        [sys.executable, "-c", f"from tests import unittest_session; unittest_session.exit_with({exited.pid}); import time; time.sleep(30)"],
        cwd=get_base_dir(),
        timeout=10,
    )
    assert result.returncode == 1
