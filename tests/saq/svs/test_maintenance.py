"""Test host maintenance windows (saq.svs.maintenance, docs/SVS_RUNS.md, *Maintenance windows*)."""

import logging
import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select, update

from saq.alert_routing import reset_alert_routers
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import DISPOSITION_IGNORE, DISPOSITION_OPEN, F_HOSTNAME, QUEUE_DEFAULT
from saq.database.model import (
    Alert,
    SVSMaintenanceAlert,
    SVSMaintenanceWindow,
    SVSRegistrationRefusal,
    SVSRun,
    User,
)
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.svs import attribution, maintenance
from saq.svs.attribution import attribution_open, evaluate
from saq.svs.constants import SVSStatus
from saq.svs.maintenance import InvalidMaintenance, MaintenanceRefused, UnknownMaintenance
from saq.svs.refusals import Caller
from saq.svs.runs import HOLDER_MAINTENANCE, HostBusy, Registration, TargetSpec, register, start
from saq.svs.service import RunTimer
from tests.saq.helpers import create_root_analysis
from tests.saq.svs.conftest import add_catalog_test, add_test_host, sync_alert

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
LAUNCHER = Caller(name="art-launcher", address="10.1.2.3")


@pytest.fixture(autouse=True)
def setup(no_hunts):
    reset_alert_routers()
    add_catalog_test(GUID)
    add_test_host("win10-01", fqdn="win10-01.lab.example", ips=["10.0.0.5"])
    add_test_host("srv-01")
    attribution.clear_caches()
    yield
    reset_alert_routers()


def _window(uuid_: str) -> SVSMaintenanceWindow:
    db = get_db()
    db.expire_all()
    return db.execute(select(SVSMaintenanceWindow).where(SVSMaintenanceWindow.uuid == uuid_)).scalar_one()


def _root(*, event_time: datetime, host: str = "win10-01", details=None) -> RootAnalysis:
    root = create_root_analysis(uuid=str(uuid.uuid4()), event_time=event_time)
    root.initialize_storage()
    root.add_observable_by_spec(F_HOSTNAME, host)
    if details:
        root.details = details
    root.add_detection_point("staging tool downloaded")
    root.save()
    return root


def _alert(uuid_: str) -> Alert:
    db = get_db()
    db.expire_all()
    return db.execute(select(Alert).where(Alert.uuid == uuid_)).unique().scalar_one()


def _records(alert_uuid: str) -> list[SVSMaintenanceAlert]:
    db = get_db()
    db.expire_all()
    return list(db.execute(select(SVSMaintenanceAlert).where(SVSMaintenanceAlert.alert_uuid == alert_uuid)).scalars())


#
# opening and ending
#

def test_open_and_end(caplog):
    caplog.set_level(logging.INFO)
    now = datetime(2026, 10, 22, 12, 0, 0)
    window = maintenance.open_window("WIN10-01.lab.example", 30, "staging mimikatz", LAUNCHER, now=now)
    window = _window(window.uuid)
    assert (window.host, window.fqdn, window.opened_at, window.ends_at, window.ended_at) == (
        "win10-01", "win10-01.lab.example", now, now + timedelta(minutes=30), None)
    assert (window.opened_by, window.reason) == ("art-launcher", "staging mimikatz")
    (opened,) = [r for r in caplog.records if r.getMessage().startswith("AUDIT: svs maintenance window opened")]
    assert (opened.svs_maintenance, opened.host, opened.minutes, opened.actor) == (
        window.uuid, "win10-01", 30, "art-launcher")

    # by the test host's id too
    host_id = window.test_host_id
    ended = maintenance.end_window(str(host_id), LAUNCHER, now=now + timedelta(minutes=5))
    window = _window(ended.uuid)
    assert (window.ended_at, window.end_reason, window.ended_by) == (now + timedelta(minutes=5), "ended", "art-launcher")
    assert any(r.getMessage().startswith("AUDIT: svs maintenance window ended") for r in caplog.records)

    with pytest.raises(UnknownMaintenance, match="no open maintenance window"):
        maintenance.end_window("win10-01", LAUNCHER, now=now + timedelta(minutes=6))


@pytest.mark.parametrize("minutes, reason, message", [
    (0, "staging", "minutes must be from 1 to 240"),
    (241, "staging", "minutes must be from 1 to 240"),
    (30, "  ", "needs a reason"),
])
def test_invalid(minutes, reason, message):
    with pytest.raises(InvalidMaintenance, match=message):
        maintenance.open_window("win10-01", minutes, reason, LAUNCHER)
    assert get_db().execute(select(SVSMaintenanceWindow)).first() is None


@pytest.mark.parametrize("host, reason", [
    ("prod-dc-01", "prod-dc-01 is not a test host"),
    ("win10-01.prod.example", "win10-01.prod.example is not test host win10-01.lab.example"),
])
def test_a_host_that_is_not_a_test_host_is_refused_and_alerts(host, reason):
    with pytest.raises(MaintenanceRefused) as error:
        maintenance.open_window(host, 30, "staging", LAUNCHER)
    assert error.value.reasons == [reason]
    assert get_db().execute(select(SVSMaintenanceWindow)).first() is None
    assert get_db().execute(select(SVSRegistrationRefusal.host)).scalars().all() == [host]
    get_db().expire_all()
    (alert,) = get_db().query(Alert).all()
    assert alert.queue == QUEUE_DEFAULT


def test_an_unknown_test_host_id():
    with pytest.raises(UnknownMaintenance):
        maintenance.open_window("999999", 30, "staging", LAUNCHER)


def test_a_window_and_a_run_never_hold_one_host_at_once():
    now = datetime.now().replace(microsecond=0)
    run = register(Registration(test_guid=GUID, targets=[TargetSpec("win10-01")], launcher="art"), LAUNCHER, now=now)
    with pytest.raises(HostBusy) as error:
        maintenance.open_window("win10-01", 30, "staging", LAUNCHER, now=now)
    assert [holder.run_uuid for holder in error.value.holders] == [run.uuid]
    # another host is free
    maintenance.open_window("srv-01", 30, "staging", LAUNCHER, now=now)

    start(run.uuid, LAUNCHER, now=now)
    later = now + timedelta(hours=2)
    window = maintenance.open_window("win10-01", 30, "staging", LAUNCHER, now=later)

    # the other way round: the window holds the host, for runs and windows alike
    for attempt in (lambda: register(Registration(test_guid=GUID, targets=[TargetSpec("win10-01")], launcher="art"),
                                     LAUNCHER, now=later + timedelta(minutes=1)),
                    lambda: maintenance.open_window("win10-01", 30, "again", LAUNCHER, now=later + timedelta(minutes=1))):
        with pytest.raises(HostBusy) as error:
            attempt()
        (holder,) = error.value.holders
        assert (holder.run_uuid, holder.state, holder.maintenance_uuid, holder.until) == (
            None, HOLDER_MAINTENANCE, window.uuid, later + timedelta(minutes=30))
        assert f"maintenance window {window.uuid}" in str(error.value)

    # once it ended, the host is free
    maintenance.end_window("win10-01", LAUNCHER, now=later + timedelta(minutes=2))
    register(Registration(test_guid=GUID, targets=[TargetSpec("win10-01")], launcher="art"), LAUNCHER,
             now=later + timedelta(minutes=3))


def test_the_timers_expire_a_window(caplog):
    now = datetime.now().replace(microsecond=0)
    window = maintenance.open_window("win10-01", 30, "staging", LAUNCHER, now=now - timedelta(hours=1))
    caplog.set_level(logging.INFO)
    assert maintenance.run_timers(now) == (1, 0)
    window = _window(window.uuid)
    assert (window.ended_at, window.end_reason, window.ended_by) == (window.ends_at, "expired", "svs")
    (record,) = [r for r in caplog.records if r.getMessage().startswith("AUDIT: svs maintenance window expired")]
    assert record.svs_maintenance == window.uuid
    assert maintenance.run_timers(now) == (0, 0)


def test_service_svs_runs_the_maintenance_timers(monkeypatch):
    calls = []
    monkeypatch.setattr(maintenance, "run_timers", lambda: calls.append(True))
    RunTimer(None).run_once()
    assert calls == [True]


#
# judging alerts
#

class TestEvaluate:
    @pytest.fixture
    def window(self):
        return maintenance.open_window("win10-01", 30, "staging", LAUNCHER, now=datetime.now() - timedelta(minutes=10))

    def test_the_gate_opens_for_a_window(self, window):
        assert attribution_open()

    def test_an_alert_inside_the_window(self, window):
        root = _root(event_time=datetime.now())
        evaluation = evaluate(root, datetime.now())
        assert evaluation.maintenance.uuid == window.uuid
        assert evaluation.status is None and evaluation.attributions == []

        # by its test host's address too
        root = RootAnalysis(uuid=str(uuid.uuid4()))
        root.add_observable_by_spec("ipv4", "10.0.0.5")
        root.add_detection_point("hit")
        assert evaluate(root, datetime.now()).maintenance is not None

    @pytest.mark.parametrize("host, offset", [
        ("srv-01", timedelta(0)),                # another host
        ("win10-01", timedelta(minutes=-20)),    # before the window
        ("win10-01", timedelta(minutes=30)),     # after it
    ])
    def test_an_alert_outside_the_window(self, window, host, offset):
        root = _root(event_time=datetime.now() + offset, host=host)
        assert evaluate(root, datetime.now() + offset).maintenance is None

    def test_an_alert_with_a_marker_is_judged_as_any_other(self, window):
        root = _root(event_time=datetime.now(), details={"cmd": "svs-" + "a" * 26})
        evaluation = evaluate(root, datetime.now())
        assert evaluation.maintenance is None and evaluation.status == SVSStatus.MISMATCH

    def test_the_window_wins_over_a_runs_late_attribution(self):
        # a run whose claim ended before the window opened, and whose attribution window covers it
        started = datetime.now().replace(microsecond=0) - timedelta(hours=3)
        run = register(Registration(test_guid=GUID, targets=[TargetSpec("win10-01")], launcher="art"), LAUNCHER,
                       now=started)
        start(run.uuid, LAUNCHER, now=started)
        attribution.clear_caches()
        window = maintenance.open_window("win10-01", 30, "staging", LAUNCHER)

        evaluation = evaluate(_root(event_time=datetime.now()), datetime.now() + timedelta(minutes=1))
        assert evaluation.maintenance.uuid == window.uuid and evaluation.attributions == []
        # and after it, the run still gets its late alerts
        after = datetime.now() + timedelta(hours=1)
        assert {a.run.uuid for a in evaluate(_root(event_time=after), after).attributions} == {run.uuid}


#
# routing and closing alerts
#

def test_an_alert_of_a_window_is_routed_recorded_and_closed(caplog):
    window_uuid = maintenance.open_window("win10-01", 30, "staging mimikatz", LAUNCHER,
                                          now=datetime.now() - timedelta(minutes=10)).uuid
    root = _root(event_time=datetime.now())
    ALERT(root)
    assert _alert(root.uuid).queue == get_config().svs.queue
    (record,) = _records(root.uuid)
    assert record.confirmed_at is None

    # not closed before its correlation pass confirms it
    assert maintenance.close_alerts() == 0
    sync_alert(root)
    (record,) = _records(root.uuid)
    assert record.confirmed_at is not None

    caplog.set_level(logging.INFO)
    assert maintenance.close_alerts() == 1
    alert = _alert(root.uuid)
    assert (alert.disposition, alert.queue) == (DISPOSITION_IGNORE, get_config().svs.queue)
    (record,) = _records(root.uuid)
    assert record.closed_at is not None
    (closed,) = [r for r in caplog.records if " closed as IGNORE" in r.getMessage()]
    assert (closed.svs_maintenance, closed.alert_uuid) == (window_uuid, root.uuid)
    assert maintenance.close_alerts() == 0


def test_an_alert_an_analyst_took_is_left_alone():
    maintenance.open_window("win10-01", 30, "staging", LAUNCHER, now=datetime.now() - timedelta(minutes=10))
    root = _root(event_time=datetime.now())
    ALERT(root)
    sync_alert(root)
    analyst = get_db().execute(select(User.id).where(User.username == "unittest")).scalar_one()
    get_db().execute(update(Alert).where(Alert.uuid == root.uuid).values(owner_id=analyst))
    get_db().commit()

    assert maintenance.close_alerts() == 0
    assert _alert(root.uuid).disposition == DISPOSITION_OPEN
    # and isn't looked at again
    assert _records(root.uuid)[0].closed_at is not None


def test_an_alert_no_longer_judged_maintenance_is_not_closed():
    maintenance.open_window("win10-01", 30, "staging", LAUNCHER, now=datetime.now() - timedelta(minutes=10))
    root = _root(event_time=datetime.now())
    ALERT(root)
    # its correlation pass finds a marker
    root.details = {"cmd": "svs-" + "b" * 26}
    root.save()
    sync_alert(root)

    (record,) = _records(root.uuid)
    assert record.removed_at is not None
    assert maintenance.close_alerts() == 0
    # a mismatch stays in triage
    assert _alert(root.uuid).queue == QUEUE_DEFAULT
