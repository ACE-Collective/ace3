import logging

import pytest

from saq.configuration.config import get_config, get_service_config
from saq.constants import DISPOSITION_FALSE_POSITIVE, SERVICE_EXTERNAL_REMEDIATION_CHECK
from saq.database.model import ExternalRemediationCheck
from saq.database.pool import get_db
from saq.remediation.external.probe import ExternalRemediationProbe
from saq.remediation.external.service import ExternalRemediationCheckService
from saq.remediation.external.types import CheckResult, CheckStatus, ProbeOutcome, ProbeTarget
from tests.saq.helpers import wait_for_condition


class NotFoundProbe(ExternalRemediationProbe):
    """A probe the service loads from an external_remediation_probe_* section."""

    def probe(self, target: ProbeTarget) -> ProbeOutcome:
        return ProbeOutcome(not_found=True)


@pytest.fixture
def probe_sections(monkeypatch):
    """Replaces the external_remediation_probe_* sections of the config with the given ones."""
    raw = get_config().raw._data
    for key in [key for key in raw if key.startswith("external_remediation_probe_")]:
        monkeypatch.delitem(raw, key)

    def _load(**sections: dict):
        for name, overrides in sections.items():
            monkeypatch.setitem(raw, f"external_remediation_probe_{name}", {
                "name": name,
                "observable_type": "email_delivery",
                "python_module": __name__,
                "python_class": "NotFoundProbe",
                "thread_count": 1,
                "initial_delay_seconds": 1,
                **overrides,
            })
        get_config().load_external_remediation_probe_configs()

    return _load


@pytest.fixture
def no_probes(probe_sections):
    """No probe is configured, so only the sweep can finish a check."""
    probe_sections()


@pytest.fixture
def service_config():
    return get_service_config(SERVICE_EXTERNAL_REMEDIATION_CHECK)


def _check(check_id: int) -> ExternalRemediationCheck:
    get_db().expire_all()
    return get_db().query(ExternalRemediationCheck).filter(ExternalRemediationCheck.id == check_id).one()


def _disposition(alert):
    alert.disposition = DISPOSITION_FALSE_POSITIVE
    get_db().commit()


@pytest.mark.integration
def test_disposition_sweep_leaves_open_alerts_and_finished_checks(make_check, db_alert):
    in_flight = make_check().id
    finished = make_check(status=CheckStatus.COMPLETED.value, result=CheckResult.NOT_FOUND.value).id

    service = ExternalRemediationCheckService()
    # the alert is still OPEN
    service._run_disposition_sweep()
    assert _check(in_flight).status == CheckStatus.NEW.value

    _disposition(db_alert)
    service._run_disposition_sweep()
    assert _check(in_flight).status == CheckStatus.COMPLETED.value
    assert _check(in_flight).result == CheckResult.CANCELLED.value
    assert _check(finished).result == CheckResult.NOT_FOUND.value


@pytest.mark.unit
def test_disposition_sweep_with_no_checks_in_flight():
    ExternalRemediationCheckService()._run_disposition_sweep()


@pytest.mark.integration
def test_service_runs_disposition_sweep(make_check, db_alert, no_probes, service_config, monkeypatch):
    service_config.stop_on_disposition = True
    service_config.disposition_sweep_interval_seconds = 1
    check_id = make_check(probe_name="unconfigured_probe").id

    service = ExternalRemediationCheckService()
    passes = []
    sweep = service._run_disposition_sweep

    def _counted_sweep():
        sweep()
        passes.append(None)

    monkeypatch.setattr(service, "_run_disposition_sweep", _counted_sweep)
    service.start()
    try:
        assert service.wait_for_start(5)
        # a pass while the alert is still open leaves its check alone
        wait_for_condition(lambda: passes)
        assert _check(check_id).status == CheckStatus.NEW.value

        _disposition(db_alert)
        wait_for_condition(lambda: _check(check_id).result == CheckResult.CANCELLED.value)
    finally:
        service.stop()
        service.wait()

    assert not service._sweep_thread.is_alive()


@pytest.mark.integration
def test_service_without_disposition_sweep(make_check, db_alert, no_probes):
    check_id = make_check(probe_name="unconfigured_probe").id
    _disposition(db_alert)

    service = ExternalRemediationCheckService()
    service.start()
    service.stop()
    service.wait()

    assert service._sweep_thread is None
    assert _check(check_id).status == CheckStatus.NEW.value


@pytest.mark.unit
def test_disposition_sweep_loop_logs_failures_and_keeps_going(monkeypatch, caplog):
    service = ExternalRemediationCheckService()
    calls = []

    def _sweep():
        calls.append(None)
        if len(calls) == 2:
            service._sweep_shutdown.set()
        raise RuntimeError("database is gone")

    def _remove():
        raise RuntimeError("pool is gone")

    monkeypatch.setattr(service, "_run_disposition_sweep", _sweep)
    monkeypatch.setattr("saq.remediation.external.service.remove_all_sessions", _remove)

    service._disposition_sweep_loop(0)

    assert len(calls) == 2
    errors = [r for r in caplog.records if r.levelno == logging.ERROR and r.exc_info]
    assert sum("disposition sweep failed" in r.getMessage() for r in errors) == 2
    assert sum("error removing database connection" in r.getMessage() for r in errors) == 2


@pytest.mark.integration
def test_start_single_threaded_probes_everything_due(make_check, probe_sections):
    probe_sections(fake_probe={}, disabled_probe={"enabled": False})
    ids = [make_check().id, make_check().id, make_check(probe_name="disabled_probe").id]

    service = ExternalRemediationCheckService()
    service.start_single_threaded()

    assert set(service.manager.workers) == {"fake_probe"}
    assert [_check(check_id).result for check_id in ids[:2]] == [CheckResult.NOT_FOUND.value] * 2
    assert _check(ids[2]).status == CheckStatus.NEW.value

    # `ace service start` stops and waits for the service after it returns
    service.stop()
    service.wait()


@pytest.mark.integration
def test_start_single_threaded_stops_on_shutdown(make_check, probe_sections, monkeypatch):
    probe_sections(fake_probe={})
    ids = [make_check().id for _ in range(3)]
    # shutdown is requested (as a signal would) while the first item is being worked
    checks = iter([False])
    monkeypatch.setattr("saq.remediation.external.worker.is_shutting_down", lambda: next(checks, True))

    service = ExternalRemediationCheckService()
    service.start_single_threaded()

    assert [_check(check_id).result for check_id in ids].count(CheckResult.NOT_FOUND.value) == 1
    service.stop()
    service.wait()


@pytest.mark.integration
def test_start_single_threaded_sweeps_dispositioned_alerts_once(make_check, db_alert, no_probes, service_config):
    service_config.stop_on_disposition = True
    check_id = make_check(probe_name="unconfigured_probe").id
    _disposition(db_alert)

    service = ExternalRemediationCheckService()
    service.start_single_threaded()

    assert _check(check_id).result == CheckResult.CANCELLED.value
    service.stop()
    service.wait()


@pytest.mark.integration
def test_service_lifecycle(make_check, probe_sections):
    probe_sections(fake_probe={})
    check_id = make_check().id

    service = ExternalRemediationCheckService()
    service.start()
    try:
        assert service.wait_for_start(5)
        wait_for_condition(lambda: _check(check_id).result == CheckResult.NOT_FOUND.value)
    finally:
        service.stop()
        service.wait()

    assert not service.manager.collector.collector_thread.is_alive()
    assert all(not thread.is_alive() for worker in service.manager.workers.values() for thread in worker.worker_threads)


@pytest.mark.unit
def test_service_passes_config_to_manager(service_config, no_probes):
    service_config.lock_timeout_seconds = 11
    service_config.initial_retry_delay_seconds = 12
    service_config.max_retry_delay_seconds = 13

    collector = ExternalRemediationCheckService()._create_manager(service_config).collector

    assert (collector.lock_timeout_seconds, collector.initial_retry_delay_seconds, collector.max_retry_delay_seconds) == (11, 12, 13)
