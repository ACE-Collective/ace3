import logging
from unittest.mock import patch

import pytest

from saq.configuration.config import get_service_config
from saq.configuration.yaml_parser import YAMLConfig
from saq.constants import SERVICE_MONITORING
from saq.monitoring.service import ACEMonitoringService, ACEMonitoringServiceConfig, ThreadedMonitorConfig
from tests.saq.helpers import wait_for_condition
from tests.saq.monitoring.conftest import ConcreteTestMonitor


@pytest.fixture
def set_monitors(monkeypatch):
    def _set(monitors):
        monkeypatch.setattr(get_service_config(SERVICE_MONITORING), "monitors", monitors)
    return _set


def _make_monitor_config(python_module, python_class, frequency=1.0, enabled=True):
    return ThreadedMonitorConfig(
        python_module=python_module,
        python_class=python_class,
        frequency=frequency,
        enabled=enabled,
    )


def _make_test_monitor_config(frequency=0.1, enabled=True):
    return _make_monitor_config("tests.saq.monitoring.conftest", "ConcreteTestMonitor",
                                frequency=frequency, enabled=enabled)


@pytest.mark.unit
class TestACEMonitoringService:
    def test_get_config_class(self):
        assert ACEMonitoringService.get_config_class() is ACEMonitoringServiceConfig

    def test_init_loads_monitors_from_config(self, set_monitors):
        set_monitors({
            "loaded_monitor": _make_monitor_config(
                python_module="tests.saq.monitoring.conftest",
                python_class="ConcreteTestMonitor",
                frequency=2.0,
            ),
        })

        service = ACEMonitoringService()
        assert len(service.threaded_monitors) == 1
        assert service.threaded_monitors[0].name == "loaded_monitor"
        assert service.threaded_monitors[0].frequency == 2.0

    def test_init_with_no_monitors(self, set_monitors):
        set_monitors({})

        service = ACEMonitoringService()
        assert service.threaded_monitors == []

    @patch("saq.error.reporting.write_error_report")
    def test_load_catches_import_error(self, mock_report, set_monitors):
        set_monitors({
            "bad_import": _make_monitor_config(
                python_module="nonexistent.module",
                python_class="FakeClass",
            ),
        })

        service = ACEMonitoringService()
        assert service.threaded_monitors == []
        mock_report.assert_called_once()

    @patch("saq.error.reporting.write_error_report")
    def test_load_catches_attribute_error(self, mock_report, set_monitors):
        set_monitors({
            "bad_class": _make_monitor_config(
                python_module="tests.saq.monitoring.conftest",
                python_class="NonexistentClass",
            ),
        })

        service = ACEMonitoringService()
        assert service.threaded_monitors == []
        mock_report.assert_called_once()

    def test_load_passes_name_and_frequency(self, set_monitors):
        set_monitors({
            "named_monitor": _make_monitor_config(
                python_module="tests.saq.monitoring.conftest",
                python_class="ConcreteTestMonitor",
                frequency=7.5,
            ),
        })

        service = ACEMonitoringService()
        monitor = service.threaded_monitors[0]
        assert monitor.name == "named_monitor"
        assert monitor.frequency == 7.5

    def test_start_stop_wait_drive_the_loaded_monitors(self, set_monitors):
        set_monitors({"looping_monitor": _make_test_monitor_config()})

        service = ACEMonitoringService()
        monitor = service.threaded_monitors[0]

        service.start()
        try:
            wait_for_condition(lambda: monitor.execute_count >= 2)
        finally:
            service.stop()
            service.wait()

        assert monitor.shutdown_event.is_set()
        assert not monitor.main_thread.is_alive()

    def test_start_single_threaded_executes_each_monitor_once(self, set_monitors):
        set_monitors({
            "monitor_a": _make_test_monitor_config(),
            "monitor_b": _make_test_monitor_config(),
        })

        service = ACEMonitoringService()
        service.start_single_threaded()

        assert [m.execute_count for m in service.threaded_monitors] == [1, 1]

    def test_wait_for_start_returns_false_when_a_monitor_never_starts(self, set_monitors):
        set_monitors({})

        service = ACEMonitoringService()
        service.threaded_monitors = [ConcreteTestMonitor()]

        assert service.wait_for_start(timeout=0.1) is False

    def test_disabled_monitor_is_not_loaded(self, set_monitors):
        set_monitors({
            "disabled_monitor": _make_monitor_config(
                python_module="tests.saq.monitoring.conftest",
                python_class="ConcreteTestMonitor",
                enabled=False,
            ),
        })

        service = ACEMonitoringService()
        assert service.threaded_monitors == []

    def test_disabled_monitor_logs_info(self, set_monitors, caplog):
        set_monitors({
            "disabled_monitor": _make_monitor_config(
                python_module="tests.saq.monitoring.conftest",
                python_class="ConcreteTestMonitor",
                enabled=False,
            ),
        })

        with caplog.at_level(logging.INFO):
            service = ACEMonitoringService()

        assert any("disabled_monitor" in msg and "disabled" in msg for msg in caplog.messages)

    def test_enabled_defaults_to_true(self):
        config = ThreadedMonitorConfig(
            python_module="some.module",
            python_class="SomeClass",
        )
        assert config.enabled is True

    def test_mixed_enabled_and_disabled(self, set_monitors):
        set_monitors({
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
