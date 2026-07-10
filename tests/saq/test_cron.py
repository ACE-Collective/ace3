import asyncio
import signal

import pytest

from saq.cron import ACECronConfig, ACECronService


class MockCron:
    """Mock of yacron.cron.Cron.

    the real Cron schedules and forks actual cron jobs, so it is always mocked here
    """

    def __init__(self, config_arg):
        self.config_arg = config_arg
        self.ran = False
        self.shutdown_signaled = False
        # signal dispositions observed from inside run(), while the loop is running
        self.handlers_during_run = {}
        self.exception_to_raise = None

    async def run(self):
        self.ran = True
        for sig in (signal.SIGINT, signal.SIGTERM):
            self.handlers_during_run[sig] = signal.getsignal(sig)

        if self.exception_to_raise:
            raise self.exception_to_raise

    def signal_shutdown(self):
        self.shutdown_signaled = True


class MockCronFactory:
    """collects the MockCron instances saq.cron.ACECronService constructs"""

    def __init__(self):
        self.created = []
        # when set, the next constructed MockCron raises this out of run()
        self.exception_to_raise = None

    def __call__(self, config_arg):
        cron = MockCron(config_arg)
        cron.exception_to_raise = self.exception_to_raise
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
    """patches get_service_config to return a valid cron service config"""
    config_path = tmpdir.join("cron.yaml")
    config_path.write("jobs: []\n")

    config = ACECronConfig(
        name="cron",
        description="cron service",
        enabled=True,
        python_module="saq.cron",
        python_class="ACECronService",
        cron_config_path=str(config_path),
    )

    monkeypatch.setattr("saq.cron.get_service_config", lambda name: config)
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
        """test that start() creates an event loop and runs the cron

        regression test for python 3.14, where asyncio.get_event_loop() raises
        RuntimeError instead of implicitly creating a loop for the main thread
        """
        ACECronService().start()

        assert len(mock_cron) == 1
        assert mock_cron[0].ran

    def test_start_uses_configured_cron_config_path(self, mock_cron, cron_config):
        """test that the configured cron_config_path is passed to Cron"""
        ACECronService().start()

        assert mock_cron[0].config_arg == cron_config.cron_config_path

    def test_start_leaves_no_running_loop(self, mock_cron, cron_config):
        """test that the event loop is closed and unset after start() returns"""
        ACECronService().start()

        with pytest.raises(RuntimeError):
            asyncio.get_running_loop()

    def test_signal_handlers_installed_during_run(self, mock_cron, cron_config):
        """test that SIGINT/SIGTERM are wired to the cron while it is running"""
        signal.signal(signal.SIGTERM, signal.SIG_DFL)

        ACECronService().start()

        # asyncio installs its own handler for any signal passed to add_signal_handler
        for sig in (signal.SIGINT, signal.SIGTERM):
            assert mock_cron[0].handlers_during_run[sig] not in (
                signal.SIG_DFL,
                signal.default_int_handler,
            )

    def test_signal_handlers_removed_after_run(self, mock_cron, cron_config):
        """test that the signal handlers are removed once the cron finishes"""
        signal.signal(signal.SIGTERM, signal.SIG_DFL)

        ACECronService().start()

        assert signal.getsignal(signal.SIGTERM) == signal.SIG_DFL
        assert signal.getsignal(signal.SIGINT) == signal.default_int_handler

    def test_signal_handlers_removed_when_cron_raises(self, mock_cron, cron_config):
        """test that the signal handlers are removed even if the cron raises"""
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        mock_cron.exception_to_raise = ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            ACECronService().start()

        assert signal.getsignal(signal.SIGTERM) == signal.SIG_DFL
