import logging
from threading import Event

import pytest

from saq.configuration.config import get_config, get_service_config
from saq.constants import DISPOSITION_FALSE_POSITIVE, SERVICE_EXTERNAL_REMEDIATION_CHECK
from saq.database.model import ExternalRemediationCheck
from saq.database.pool import get_db
from saq.remediation.external.service import ExternalRemediationCheckService
from saq.remediation.external.types import CheckResult, CheckStatus
from tests.saq.helpers import wait_for_condition


@pytest.fixture
def no_probes(monkeypatch):
    """Removes every external_remediation_probe_* section, so only the sweep finishes a check."""
    raw = get_config().raw._data
    for key in [key for key in raw if key.startswith("external_remediation_probe_")]:
        monkeypatch.delitem(raw, key)
    get_config().load_external_remediation_probe_configs()


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
    service._sweep_shutdown = Event()
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
