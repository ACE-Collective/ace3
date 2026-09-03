from unittest.mock import MagicMock, patch

import pytest

from saq.configuration.yaml_parser import YAMLConfig
from saq.monitoring.service import ACEMonitoringService, ACEMonitoringServiceConfig, ThreadedMonitorConfig


def _make_service_config(monitors=None):
    """Build an ACEMonitoringServiceConfig with the given monitors, keyed by name."""
    if monitors is None:
        monitors = {}
    return ACEMonitoringServiceConfig(
        name="monitoring",
        description="test monitoring service",
        enabled=True,
        python_module="saq.monitoring.service",
        python_class="ACEMonitoringService",
        monitors=monitors,
    )


def _make_monitor_config(python_module, python_class, frequency=1.0, enabled=True):
    return ThreadedMonitorConfig(
        python_module=python_module,
        python_class=python_class,
        frequency=frequency,
        enabled=enabled,
    )


@pytest.mark.unit
class TestACEMonitoringService:
    def test_get_config_class(self):
        assert ACEMonitoringService.get_config_class() is ACEMonitoringServiceConfig

    @patch("saq.monitoring.service.get_config")
    def test_init_loads_monitors_from_config(self, mock_get_config):
        config = _make_service_config(monitors={
            "loaded_monitor": _make_monitor_config(
                python_module="tests.saq.monitoring.conftest",
                python_class="ConcreteTestMonitor",
                frequency=2.0,
            ),
        })
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        assert len(service.threaded_monitors) == 1
        assert service.threaded_monitors[0].name == "loaded_monitor"
        assert service.threaded_monitors[0].frequency == 2.0

    @patch("saq.monitoring.service.get_config")
    def test_init_with_no_monitors(self, mock_get_config):
        config = _make_service_config(monitors={})
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        assert service.threaded_monitors == []

    @patch("saq.monitoring.service.report_exception")
    @patch("saq.monitoring.service.get_config")
    def test_load_catches_import_error(self, mock_get_config, mock_report):
        config = _make_service_config(monitors={
            "bad_import": _make_monitor_config(
                python_module="nonexistent.module",
                python_class="FakeClass",
            ),
        })
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        assert service.threaded_monitors == []
        mock_report.assert_called_once()

    @patch("saq.monitoring.service.report_exception")
    @patch("saq.monitoring.service.get_config")
    def test_load_catches_attribute_error(self, mock_get_config, mock_report):
        config = _make_service_config(monitors={
            "bad_class": _make_monitor_config(
                python_module="tests.saq.monitoring.conftest",
                python_class="NonexistentClass",
            ),
        })
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        assert service.threaded_monitors == []
        mock_report.assert_called_once()

    @patch("saq.monitoring.service.get_config")
    def test_load_passes_name_and_frequency(self, mock_get_config):
        config = _make_service_config(monitors={
            "named_monitor": _make_monitor_config(
                python_module="tests.saq.monitoring.conftest",
                python_class="ConcreteTestMonitor",
                frequency=7.5,
            ),
        })
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        monitor = service.threaded_monitors[0]
        assert monitor.name == "named_monitor"
        assert monitor.frequency == 7.5

    @patch("saq.monitoring.service.get_config")
    def test_start_delegates_to_monitors(self, mock_get_config):
        config = _make_service_config(monitors={})
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        mock_monitor = MagicMock()
        service.threaded_monitors = [mock_monitor]

        service.start()
        mock_monitor.start.assert_called_once()

    @patch("saq.monitoring.service.get_config")
    def test_stop_delegates_to_monitors(self, mock_get_config):
        config = _make_service_config(monitors={})
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        mock_monitor = MagicMock()
        service.threaded_monitors = [mock_monitor]

        service.stop()
        mock_monitor.stop.assert_called_once()

    @patch("saq.monitoring.service.get_config")
    def test_wait_delegates_to_monitors(self, mock_get_config):
        config = _make_service_config(monitors={})
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        mock_monitor = MagicMock()
        service.threaded_monitors = [mock_monitor]

        service.wait()
        mock_monitor.wait.assert_called_once()

    @patch("saq.monitoring.service.get_config")
    def test_start_single_threaded_delegates(self, mock_get_config):
        config = _make_service_config(monitors={})
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        mock_monitor = MagicMock()
        service.threaded_monitors = [mock_monitor]

        service.start_single_threaded()
        mock_monitor.start_single_threaded.assert_called_once()

    @patch("saq.monitoring.service.get_config")
    def test_wait_for_start_returns_false_on_failure(self, mock_get_config):
        config = _make_service_config(monitors={})
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        mock_monitor = MagicMock()
        mock_monitor.wait_for_start.return_value = False
        service.threaded_monitors = [mock_monitor]

        assert service.wait_for_start(timeout=0.1) is False

    @patch("saq.monitoring.service.get_config")
    def test_disabled_monitor_is_not_loaded(self, mock_get_config):
        config = _make_service_config(monitors={
            "disabled_monitor": _make_monitor_config(
                python_module="tests.saq.monitoring.conftest",
                python_class="ConcreteTestMonitor",
                enabled=False,
            ),
        })
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        assert service.threaded_monitors == []

    @patch("saq.monitoring.service.get_config")
    def test_disabled_monitor_logs_info(self, mock_get_config, caplog):
        config = _make_service_config(monitors={
            "disabled_monitor": _make_monitor_config(
                python_module="tests.saq.monitoring.conftest",
                python_class="ConcreteTestMonitor",
                enabled=False,
            ),
        })
        mock_get_config.return_value.get_service_config.return_value = config

        import logging
        with caplog.at_level(logging.INFO):
            service = ACEMonitoringService()

        assert any("disabled_monitor" in msg and "disabled" in msg for msg in caplog.messages)

    def test_enabled_defaults_to_true(self):
        config = ThreadedMonitorConfig(
            python_module="some.module",
            python_class="SomeClass",
        )
        assert config.enabled is True

    @patch("saq.monitoring.service.get_config")
    def test_mixed_enabled_and_disabled(self, mock_get_config):
        config = _make_service_config(monitors={
            "monitor_a": _make_monitor_config(
                python_module="tests.saq.monitoring.conftest",
                python_class="ConcreteTestMonitor",
                enabled=True,
            ),
            "monitor_b": _make_monitor_config(
                python_module="tests.saq.monitoring.conftest",
                python_class="ConcreteTestMonitor",
                enabled=False,
            ),
            "monitor_c": _make_monitor_config(
                python_module="tests.saq.monitoring.conftest",
                python_class="ConcreteTestMonitor",
                enabled=True,
            ),
        })
        mock_get_config.return_value.get_service_config.return_value = config

        service = ACEMonitoringService()
        assert len(service.threaded_monitors) == 2
        names = [m.name for m in service.threaded_monitors]
        assert "monitor_a" in names
        assert "monitor_b" not in names
        assert "monitor_c" in names


@pytest.mark.unit
def test_overlay_can_disable_a_default_monitor(tmp_path):
    """A later configuration file must be able to disable a monitor an earlier one defined.

    This is the level the bug actually lived at: the monitors block goes through
    YAMLConfig.merge() before it is ever validated, and a mapping merges by key while a
    list appends (saq/configuration/yaml_parser.py). The overlay carries nothing but
    enabled: false -- everything else has to survive the merge.
    """
    base = tmp_path / "base.yaml"
    base.write_text("""
service_monitoring:
  name: monitoring
  python_module: saq.monitoring.service
  python_class: ACEMonitoringService
  description: test monitoring service
  enabled: true
  monitors:
    local_workload:
      python_module: tests.saq.monitoring.conftest
      python_class: ConcreteTestMonitor
      frequency: 5
""")

    overlay = tmp_path / "overlay.yaml"
    overlay.write_text("""
service_monitoring:
  monitors:
    local_workload:
      enabled: false
""")

    config = YAMLConfig()
    config.load_file(str(base))
    config.load_file(str(overlay))

    validated = ACEMonitoringServiceConfig.model_validate(config._data["service_monitoring"])
    assert validated.monitors["local_workload"].enabled is False
    assert validated.monitors["local_workload"].python_class == "ConcreteTestMonitor"
    assert validated.monitors["local_workload"].frequency == 5
