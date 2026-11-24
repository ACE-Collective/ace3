"""The alert_automation service: it sweeps the configured rules on the primary node and stays idle
on the others."""

import logging
import threading

import pytest

from saq.alert_automation.service import AlertAutomationService
from saq.configuration.config import get_config
from saq.constants import DISPOSITION_DELIVERY, DISPOSITION_OPEN, ENV_ACE_IS_PRIMARY_NODE
from tests.saq.alert_automation.conftest import DELIVERY_ALICE, confirm, make_alert, rule_config, runs
from tests.saq.helpers import alert_row, search_log, wait_for_condition

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("remediable")]


@pytest.fixture(autouse=True)
def configured_rule():
    get_config().raw._data["alert_automation_rule_unittest"] = rule_config()
    get_config().load_alert_automation_rule_configs()


def test_a_single_threaded_service_sweeps_the_rules_once(monkeypatch):
    monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "1")
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)

    service = AlertAutomationService()
    service.start_single_threaded()
    service.wait()

    assert alert_row(alert_uuid).disposition == DISPOSITION_DELIVERY


def test_a_non_primary_node_stays_idle(monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "0")
    alert_uuid = make_alert(DELIVERY_ALICE)
    confirm(alert_uuid, DELIVERY_ALICE)

    service = AlertAutomationService()
    service.start()
    service.start_single_threaded()
    service.wait()

    assert service.thread is None
    assert alert_row(alert_uuid).disposition == DISPOSITION_OPEN
    assert runs(alert_uuid) == []
    assert "alert automation runs on the primary node only" in caplog.text


def test_the_service_sweeps_until_it_is_stopped(monkeypatch):
    monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "1")
    get_config().get_service_config("alert_automation").interval_seconds = 1
    service = AlertAutomationService()
    service.start()
    try:
        # an alert confirmed after the first sweep is acted on by a later one
        alert_uuid = make_alert(DELIVERY_ALICE)
        confirm(alert_uuid, DELIVERY_ALICE)
        assert wait_for_condition(lambda: alert_row(alert_uuid).disposition == DISPOSITION_DELIVERY, timeout=15)
    finally:
        service.stop()
        waiter = threading.Thread(target=service.wait, daemon=True)
        waiter.start()
        waiter.join(timeout=10)

    assert not waiter.is_alive()
    assert not service.thread.is_alive()


def test_a_rule_whose_sweep_fails_is_logged_and_the_service_goes_on(monkeypatch, caplog):
    monkeypatch.setenv(ENV_ACE_IS_PRIMARY_NODE, "1")

    def broken(*args, **kwargs):
        raise RuntimeError("the database went away")

    monkeypatch.setattr("saq.alert_automation.rules.pending_runs", broken)
    service = AlertAutomationService()
    service.start_single_threaded()

    assert search_log("alert automation rule confirmed_removal sweep failed")
    assert any(r.levelno == logging.ERROR and getattr(r, "rule", None) == "confirmed_removal" and r.exc_info
               for r in caplog.records)
