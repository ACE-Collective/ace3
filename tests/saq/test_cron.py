import asyncio
import os
import signal
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

from saq.configuration.config import get_service_config
from saq.constants import SERVICE_CRON
from saq.cron import ACECronConfig, ACECronService


class MockCron:
    """Mock of yacron.cron.Cron.

    the real Cron schedules and forks actual cron jobs, so it is always mocked here
    """

    def __init__(self, config_arg):
        self.config_arg = config_arg
        self.ran = False
        self.shutdown_signaled = False
        self.exception_to_raise = None
        # when set, run() sends this signal to the process and waits for it to arrive
        self.signal_to_send = None

    async def run(self):
        self.ran = True
        if self.exception_to_raise:
            raise self.exception_to_raise

        if self.signal_to_send:
            os.kill(os.getpid(), self.signal_to_send)
            # asyncio runs the handler on a later iteration of the loop
            for _ in range(100):
                if self.shutdown_signaled:
                    break
                await asyncio.sleep(0.01)

    def signal_shutdown(self):
        self.shutdown_signaled = True


class MockCronFactory:
    """collects the MockCron instances saq.cron.ACECronService constructs"""

    def __init__(self):
        self.created = []
        # when set, the next constructed MockCron raises this out of run()
        self.exception_to_raise = None
        # when set, the next constructed MockCron sends this signal from inside run()
        self.signal_to_send = None

    def __call__(self, config_arg):
        cron = MockCron(config_arg)
        cron.exception_to_raise = self.exception_to_raise
        cron.signal_to_send = self.signal_to_send
        self.created.append(cron)
        return cron

    def __len__(self):
        return len(self.created)

    def __getitem__(self, index):
        return self.created[index]


@pytest.fixture
def mock_cron(monkeypatch):
    """patches saq.cron.Cron and returns the factory that records what was constructed"""
    factory = MockCronFactory()
    monkeypatch.setattr("saq.cron.Cron", factory)
    return factory


@pytest.fixture
def cron_config(monkeypatch, tmpdir):
    """points the real cron service config at an empty cron.yaml"""
    config_path = tmpdir.join("cron.yaml")
    config_path.write("jobs: []\n")

    config = get_service_config(SERVICE_CRON)
    monkeypatch.setattr(config, "cron_config_path", str(config_path))
    return config


@pytest.fixture(autouse=True)
def restore_signal_handlers():
    """the service installs (and removes) SIGINT/SIGTERM handlers, so restore them after"""
    saved = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    yield
    for sig, handler in saved.items():
        signal.signal(sig, handler)


@pytest.mark.unit
class TestACECronService:
    def test_start_runs_cron_to_completion(self, mock_cron, cron_config):
        """test that start() creates an event loop and runs the cron, with the configured path

        regression test for python 3.14, where asyncio.get_event_loop() raises
        RuntimeError instead of implicitly creating a loop for the main thread
        """
        ACECronService().start()

        assert len(mock_cron) == 1
        assert mock_cron[0].ran
        assert mock_cron[0].config_arg == cron_config.cron_config_path

    @pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM])
    def test_a_shutdown_signal_reaches_the_coordinator_and_the_cron(self, mock_cron, cron_config, monkeypatch, sig):
        """the coordinator's watchdog is what bounds yacron's wait for its running jobs, and
        signal_shutdown is what makes yacron stop at all"""
        # without the service's own handler this one takes the signal, instead of it ending pytest
        signal.signal(sig, lambda signum, frame: None)
        coordinator = Mock()
        monkeypatch.setattr("saq.cron.get_shutdown_coordinator", lambda: coordinator)
        mock_cron.signal_to_send = sig

        ACECronService().start()

        coordinator.request_shutdown.assert_called_once_with("received shutdown signal")
        assert mock_cron[0].shutdown_signaled

    def test_start_passes_on_a_failure_of_the_cron(self, mock_cron, cron_config):
        mock_cron.exception_to_raise = ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            ACECronService().start()


CRON_CONFIG_PATH = Path(__file__).resolve().parents[2] / "etc" / "cron.yaml"


@pytest.mark.unit
class TestShippedCronConfig:
    """guards etc/cron.yaml itself, which nothing else exercises"""

    @pytest.fixture
    def jobs(self):
        with open(CRON_CONFIG_PATH, "r", encoding="utf-8") as fp:
            return yaml.safe_load(fp)["jobs"]

    def test_every_job_is_wrapped(self, jobs):
        """every job goes through bin/run-cron-job, so every run produces an outcome record

        the wrapper owns the log file now -- a bare shell redirect would take the job's
        output back out of the record and leave a failure with nothing to alert on
        """
        assert jobs

        for job in jobs:
            assert job["command"].startswith("/opt/ace/bin/run-cron-job "), job["name"]
            assert ">>" not in job["command"], job["name"]
            assert "2>&1" not in job["command"], job["name"]

    def test_every_referenced_script_is_executable(self, jobs):
        """catches a rename in bin/ silently breaking a scheduled job"""
        for job in jobs:
            # run-cron-job <slug> <script> [args...]
            script = job["command"].split()[2]
            assert os.access(script, os.X_OK), "{}: {} is not executable".format(job["name"], script)

    def test_every_job_forbids_concurrent_runs(self, jobs):
        """none of these jobs are safe to overlap with themselves"""
        for job in jobs:
            assert job.get("concurrencyPolicy") == "Forbid", job["name"]


@pytest.mark.unit
class TestACECronConfig:
    def _config(self, **kwargs):
        return ACECronConfig(
            name="cron",
            description="cron service",
            enabled=True,
            python_module="saq.cron",
            python_class="ACECronService",
            cron_config_path="etc/cron.yaml",
            **kwargs,
        )

    def test_max_parallel_tasks_defaults_to_unset(self):
        assert self._config().max_parallel_tasks is None

    def test_max_parallel_tasks_accepts_one(self):
        assert self._config(max_parallel_tasks=1).max_parallel_tasks == 1

    def test_max_parallel_tasks_rejects_zero(self):
        with pytest.raises(ValueError, match="greater than or equal to 1"):
            self._config(max_parallel_tasks=0)
