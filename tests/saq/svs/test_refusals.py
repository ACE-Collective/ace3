"""Refused run registrations (saq.svs.refusals, docs/SVS_RUNS.md, *Refused registrations*)."""

import logging
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from saq.constants import F_HOSTNAME, F_IPV4, F_USER, QUEUE_DEFAULT
from saq.database.model import Alert, SVSRegistrationRefusal, load_alert
from saq.database.pool import get_db
from saq.signatures.builtin import SVS_REGISTRATION_REFUSED
from saq.svs import refusals
from saq.svs.refusals import Caller, prune_refusals, refuse

pytestmark = pytest.mark.integration

CALLER = Caller(name="art-launcher", user_id=None, key_id=7, address="10.1.2.3")
T0 = datetime(2026, 10, 14, 12, 10, 0)


def _rows() -> list[SVSRegistrationRefusal]:
    db = get_db()
    db.expire_all()
    return list(db.execute(select(SVSRegistrationRefusal).order_by(SVSRegistrationRefusal.id)).scalars())


def _alerts() -> list[Alert]:
    db = get_db()
    db.expire_all()
    return db.query(Alert).all()


def test_the_first_refusal_alerts(caplog):
    with caplog.at_level(logging.WARNING):
        alert_uuid = refuse(CALLER, "PROD-DC-01.corp.example", "CORP\\administrator", "prod-dc-01 is not a test host",
                            launcher="art", test_guid="aaaaaaaa-1111-4111-8111-111111111111",
                            payload={"launcher": "art"}, now=T0)

    assert alert_uuid is not None
    (alert,) = _alerts()
    assert (alert.uuid, alert.queue, alert.alert_type, alert.tool) == (
        alert_uuid, QUEUE_DEFAULT, refusals.ALERT_TYPE, refusals.TOOL)

    root = load_alert(alert_uuid).root_analysis
    root.load()
    observables = {(o.type, o.value) for o in root.all_observables}
    assert {(F_HOSTNAME, "PROD-DC-01.corp.example"), (F_USER, "administrator"), (F_USER, "art-launcher"),
            (F_IPV4, "10.1.2.3")} <= observables
    (detection,) = root.all_detection_points
    assert detection.signature_uuid == SVS_REGISTRATION_REFUSED.uuid
    assert root.details["caller_key_id"] == 7 and root.details["request"] == {"launcher": "art"}

    (row,) = _rows()
    assert (row.caller, row.host, row.hour, row.count, row.alert_uuid) == (
        "art-launcher", "prod-dc-01", datetime(2026, 10, 14, 12), 1, alert_uuid)

    (record,) = [r for r in caplog.records if r.message.startswith("svs run registration refused")]
    assert record.levelno == logging.WARNING
    assert (record.caller, record.host, record.alerted, record.alert_uuid) == (
        "art-launcher", "prod-dc-01", True, alert_uuid)


def test_refusals_collapse_per_caller_host_and_hour(caplog):
    assert refuse(CALLER, "prod-dc-01", None, "not a test host", now=T0) is not None

    caplog.clear()
    with caplog.at_level(logging.WARNING):
        assert refuse(CALLER, "PROD-DC-01.corp.example", None, "not a test host", now=T0 + timedelta(minutes=40)) is None
    assert [r.alerted for r in caplog.records if r.message.startswith("svs run registration refused")] == [False]
    (row,) = _rows()
    assert (row.count, row.last_at) == (2, T0 + timedelta(minutes=40))

    # another host, another caller, another hour each alert again
    assert refuse(CALLER, "prod-dc-02", None, "not a test host", now=T0) is not None
    assert refuse(Caller(name="other-launcher"), "prod-dc-01", None, "not a test host", now=T0) is not None
    assert refuse(CALLER, "prod-dc-01", None, "not a test host", now=T0 + timedelta(hours=1)) is not None
    assert len(_alerts()) == 4


def test_an_ipv6_caller_is_not_an_ipv4_observable():
    alert_uuid = refuse(Caller(name="art", address="::1"), "prod-dc-01", None, "not a test host", now=T0)
    root = load_alert(alert_uuid).root_analysis
    root.load()
    assert not [o for o in root.all_observables if o.type == F_IPV4]
    assert root.details["caller_address"] == "::1"


def test_a_failed_alert_still_refuses(monkeypatch, caplog):
    def broken(*args, **kwargs):
        raise RuntimeError("storage is full")

    monkeypatch.setattr(refusals, "_create_alert", broken)
    with caplog.at_level(logging.WARNING):
        assert refuse(CALLER, "prod-dc-01", None, "not a test host", now=T0) is None

    (row,) = _rows()
    assert row.alert_uuid is None
    assert "unable to create the alert" in caplog.text
    assert [r.alerted for r in caplog.records if r.message.startswith("svs run registration refused")] == [False]


def test_prune_refusals():
    refuse(CALLER, "prod-dc-01", None, "not a test host", now=T0 - timedelta(days=2))
    refuse(CALLER, "prod-dc-01", None, "not a test host", now=T0)

    assert prune_refusals(T0) == 1
    assert [row.hour for row in _rows()] == [datetime(2026, 10, 14, 12)]
