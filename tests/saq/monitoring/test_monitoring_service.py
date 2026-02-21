from unittest.mock import MagicMock, patch

import pytest

from saq.monitoring.service import ACEMonitoringService, ACEMonitoringServiceConfig, ThreadedMonitorConfig


def _make_service_config(monitors=None):
    """Build an ACEMonitoringServiceConfig with the given monitor list."""
    if monitors is None:
        monitors = []
    return ACEMonitoringServiceConfig(
        name="monitoring",
        description="test monitoring service",
        enabled=True,
        python_module="saq.monitoring.service",
        python_class="ACEMonitoringService",
        monitors=monitors,
    )


def _make_monitor_config(python_module, python_class, name="test", frequency=1.0):
    return ThreadedMonitorConfig(
        python_module=python_module,
        python_class=python_class,
        name=name,
        frequency=frequency,
    )


@pytest.mark.unit
class TestACEMonitoringService:
    def test_get_config_class(self):
        assert ACEMonitoringService.get_config_class() is ACEMonitoringServiceConfig

    @patch("saq.monitoring.service.get_config")
    def test_init_loads_monitors_from_config(self, mock_get_config):
        config = _make_service_config(monitors=[
            _make_monitor_config(
                python_module="tests.saq.monitoring.conftest",
                python_class="ConcreteTestMonitor",
                name="loaded_monitor",
                frequency=2.0,
            ),
        ])
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        assert len(service.threaded_monitors) == 1
        assert service.threaded_monitors[0].name == "loaded_monitor"
        assert service.threaded_monitors[0].frequency == 2.0

    @patch("saq.monitoring.service.get_config")
    def test_init_with_empty_monitors_list(self, mock_get_config):
        config = _make_service_config(monitors=[])
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        assert service.threaded_monitors == []

    @patch("saq.monitoring.service.report_exception")
    @patch("saq.monitoring.service.get_config")
    def test_load_catches_import_error(self, mock_get_config, mock_report):
        config = _make_service_config(monitors=[
            _make_monitor_config(
                python_module="nonexistent.module",
                python_class="FakeClass",
                name="bad_import",
            ),
        ])
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        assert service.threaded_monitors == []
        mock_report.assert_called_once()

    @patch("saq.monitoring.service.report_exception")
    @patch("saq.monitoring.service.get_config")
    def test_load_catches_attribute_error(self, mock_get_config, mock_report):
        config = _make_service_config(monitors=[
            _make_monitor_config(
                python_module="tests.saq.monitoring.conftest",
                python_class="NonexistentClass",
                name="bad_class",
            ),
        ])
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        assert service.threaded_monitors == []
        mock_report.assert_called_once()

    @patch("saq.monitoring.service.get_config")
    def test_load_passes_name_and_frequency(self, mock_get_config):
        config = _make_service_config(monitors=[
            _make_monitor_config(
                python_module="tests.saq.monitoring.conftest",
                python_class="ConcreteTestMonitor",
                name="named_monitor",
                frequency=7.5,
            ),
        ])
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        monitor = service.threaded_monitors[0]
        assert monitor.name == "named_monitor"
        assert monitor.frequency == 7.5

    @patch("saq.monitoring.service.get_config")
    def test_start_delegates_to_monitors(self, mock_get_config):
        config = _make_service_config(monitors=[])
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        mock_monitor = MagicMock()
        service.threaded_monitors = [mock_monitor]

        service.start()
        mock_monitor.start.assert_called_once()

    @patch("saq.monitoring.service.get_config")
    def test_stop_delegates_to_monitors(self, mock_get_config):
        config = _make_service_config(monitors=[])
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        mock_monitor = MagicMock()
        service.threaded_monitors = [mock_monitor]

        service.stop()
        mock_monitor.stop.assert_called_once()

    @patch("saq.monitoring.service.get_config")
    def test_wait_delegates_to_monitors(self, mock_get_config):
        config = _make_service_config(monitors=[])
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        mock_monitor = MagicMock()
        service.threaded_monitors = [mock_monitor]

        service.wait()
        mock_monitor.wait.assert_called_once()

    @patch("saq.monitoring.service.get_config")
    def test_start_single_threaded_delegates(self, mock_get_config):
        config = _make_service_config(monitors=[])
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        mock_monitor = MagicMock()
        service.threaded_monitors = [mock_monitor]

        service.start_single_threaded()
        mock_monitor.start_single_threaded.assert_called_once()

    @patch("saq.monitoring.service.get_config")
    def test_wait_for_start_returns_false_on_failure(self, mock_get_config):
        config = _make_service_config(monitors=[])
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        mock_monitor = MagicMock()
        mock_monitor.wait_for_start.return_value = False
        service.threaded_monitors = [mock_monitor]

        assert service.wait_for_start(timeout=0.1) is False
