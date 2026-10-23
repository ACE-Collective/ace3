"""Test host maintenance windows (saq.svs.maintenance, docs/SVS_RUNS.md, *Maintenance windows*)."""

import logging
import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select, update

from saq.alert_routing import reset_alert_routers
from saq.analysis.analysis import Analysis
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_config
from saq.constants import DISPOSITION_IGNORE, DISPOSITION_OPEN, F_HOSTNAME, F_TEST, QUEUE_DEFAULT
from saq.database.model import (
    Alert,
    SVSMaintenanceAlert,
    SVSMaintenanceWindow,
    SVSRegistrationRefusal,
    SVSRun,
    SVSTestHost,
    User,
)
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.engine.execution_context import EngineExecutionContext
from saq.svs import attribution, hosts, maintenance, service
from saq.svs.association import associate, disassociate
from saq.svs.attribution import attribution_open, evaluate, record_suppressed_matches, suppression_key, suppression_owners
from saq.svs.constants import SVSStatus
from saq.svs.maintenance import InvalidMaintenance, MaintenanceRefused, UnknownMaintenance
from saq.svs.refusals import Caller
from saq.svs.runs import HOLDER_MAINTENANCE, HostBusy, Registration, TargetSpec, register, start
from saq.svs.service import RunTimer
from tests.saq.helpers import create_root_analysis, create_test_orchestrator
from tests.saq.svs.conftest import add_catalog_test, add_test_host, attribute_to_run, started_run, sync_alert

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
LAUNCHER = Caller(name="art-launcher", address="10.1.2.3")
HUNT_UUID = "11111111-aaaa-4aaa-8aaa-111111111111"


class DelayedAnalysis(Analysis):
    pass


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
    ("win10 01", "'win10 01' is not a host name"),
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


def test_ending_on_a_host_that_is_not_a_test_host_is_refused_and_alerts():
    with pytest.raises(MaintenanceRefused) as error:
        maintenance.end_window("win10 01", LAUNCHER)
    assert error.value.reasons == ["'win10 01' is not a host name"]
    assert get_db().execute(select(SVSRegistrationRefusal.host)).scalars().all() == ["win10 01"]


def test_an_unknown_test_host_id():
    with pytest.raises(UnknownMaintenance):
        maintenance.open_window("999999", 30, "staging", LAUNCHER)


@pytest.mark.parametrize("host_ref", ["999999", "win10 01"])
def test_listing_an_unknown_or_malformed_host(host_ref):
    # reading never alerts
    with pytest.raises(UnknownMaintenance):
        maintenance.list_windows(host_ref, 10)
    assert get_db().execute(select(SVSRegistrationRefusal)).first() is None


def test_listing_pages_latest_first():
    now = datetime.now().replace(microsecond=0) - timedelta(hours=3)
    ids = []
    for hours in range(3):
        ids.append(maintenance.open_window("win10-01", 30, "staging", LAUNCHER, now=now + timedelta(hours=hours)).id)
    assert [w.id for w in maintenance.list_windows("win10-01", 2)] == [ids[2], ids[1]]
    assert [w.id for w in maintenance.list_windows("win10-01", 2, before_id=ids[1])] == [ids[0]]
    assert maintenance.list_windows("srv-01", 2) == []


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


def _host_id(hostname: str) -> int:
    return get_db().execute(select(SVSTestHost.id).where(SVSTestHost.hostname == hostname)).scalar_one()


def test_removing_the_test_host_ends_its_window(caplog):
    """Otherwise the window went on closing the alerts of a host nobody tests, and couldn't be
    ended: end_window refuses a host that is not a test host."""
    opened = datetime.now().replace(microsecond=0) - timedelta(minutes=10)
    window = maintenance.open_window("win10-01", 30, "staging", LAUNCHER, now=opened)
    other = maintenance.open_window("srv-01", 30, "staging", LAUNCHER, now=opened)

    caplog.set_level(logging.INFO)
    hosts.delete_host(_host_id("win10-01"), actor="dana")
    removed_at = datetime.now()

    window = _window(window.uuid)
    assert window.test_host_id is None
    assert (window.end_reason, window.ended_by) == ("ended", "dana")
    assert opened < window.ended_at <= removed_at
    assert _window(other.uuid).ended_at is None
    (ended,) = [r for r in caplog.records if r.getMessage().startswith("AUDIT: svs maintenance window ended")]
    assert (ended.svs_maintenance, ended.actor, ended.ended_because) == (window.uuid, "dana", "test host removed")
    (host_removed,) = [r for r in caplog.records if r.getMessage() == "AUDIT: svs test host removed"]
    assert host_removed.ended_maintenance == [window.uuid]

    # what happened before the removal is still the window's; after it, triage's
    before = window.ended_at - timedelta(minutes=1)
    assert evaluate(_root(event_time=before), before).maintenance.uuid == window.uuid
    after = window.ended_at + timedelta(seconds=1)
    assert evaluate(_root(event_time=after), after).maintenance is None


def test_a_failed_host_removal_leaves_the_window_open(monkeypatch, caplog):
    window = maintenance.open_window("win10-01", 30, "staging", LAUNCHER, now=datetime.now() - timedelta(minutes=10))
    db = get_db()

    def broken():
        raise RuntimeError("database went away")

    monkeypatch.setattr(db, "commit", broken)
    caplog.set_level(logging.INFO)
    with pytest.raises(RuntimeError, match="database went away"):
        hosts.delete_host(_host_id("win10-01"), actor="dana")
    monkeypatch.undo()
    db.rollback()

    window = _window(window.uuid)
    assert window.ended_at is None and window.test_host_id == _host_id("win10-01")
    assert not [r for r in caplog.records if r.getMessage().startswith(("AUDIT: svs maintenance window ended",
                                                                        "AUDIT: svs test host removed"))]


def test_service_svs_runs_the_maintenance_timers(monkeypatch):
    calls = []
    monkeypatch.setattr(maintenance, "run_timers", lambda: calls.append(True))
    RunTimer(None).run_once()
    assert calls == [True]


def test_a_failure_of_the_maintenance_timers_is_logged_and_the_next_pass_runs_them(monkeypatch, caplog):
    def broken():
        raise RuntimeError("database went away")

    run_timer_calls = []
    monkeypatch.setattr(service, "run_timers", lambda: run_timer_calls.append(True))
    monkeypatch.setattr(maintenance, "run_timers", broken)
    with caplog.at_level(logging.ERROR):
        RunTimer(None).run_once()
    (record,) = [r for r in caplog.records if "svs maintenance timers failed" in r.getMessage()]
    assert record.levelno == logging.ERROR and record.exc_info is not None

    # a failure of the run timers doesn't keep the maintenance timers from running either
    calls = []
    monkeypatch.setattr(service, "run_timers", broken)
    monkeypatch.setattr(maintenance, "run_timers", lambda: calls.append(True))
    RunTimer(None).run_once()
    assert calls == [True]


def test_a_window_whose_alerts_fail_to_close_doesnt_stop_the_others(monkeypatch, caplog):
    roots = []
    for host in ("win10-01", "srv-01"):
        maintenance.open_window(host, 30, "staging", LAUNCHER, now=datetime.now() - timedelta(minutes=10))
        root = _root(event_time=datetime.now(), host=host)
        ALERT(root)
        sync_alert(root)
        roots.append(root)

    close = maintenance._close_window_alerts

    def failing_on_win10(window, records, automation_user_id):
        if window.host == "win10-01":
            raise RuntimeError("deadlock")
        return close(window, records, automation_user_id)

    monkeypatch.setattr(maintenance, "_close_window_alerts", failing_on_win10)
    with caplog.at_level(logging.ERROR):
        assert maintenance.close_alerts() == 1
    (record,) = [r for r in caplog.records if "unable to close the alerts" in r.getMessage()]
    assert record.levelno == logging.ERROR and record.exc_info is not None
    assert (_alert(roots[0].uuid).disposition, _alert(roots[1].uuid).disposition) == (
        DISPOSITION_OPEN, DISPOSITION_IGNORE)
    # the failed window's alerts are tried again on the next pass
    assert _records(roots[0].uuid)[0].closed_at is None
    monkeypatch.setattr(maintenance, "_close_window_alerts", close)
    assert maintenance.close_alerts() == 1


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

    def test_a_run_on_another_host_the_alert_involves_wins(self, window):
        """The run is on its own host, so an alert that also names the window's host is the run's:
        a test that reaches from srv-01 to win10-01, say."""
        run = started_run(GUID, "srv-01", now=datetime.now().replace(microsecond=0) - timedelta(minutes=5))
        root = _root(event_time=datetime.now())
        root.add_observable_by_spec(F_HOSTNAME, "srv-01")
        evaluation = evaluate(root, datetime.now())
        assert evaluation.maintenance is None
        assert {a.run.uuid for a in evaluation.attributions} == {run.uuid}
        # what involves only the window's host is still the window's
        assert evaluate(_root(event_time=datetime.now()), datetime.now()).maintenance.uuid == window.uuid

    def test_a_persons_association_holds_over_the_window(self, window):
        """An analyst associated the alert with a run by hand: it stays the run's while the
        association stands, and is the window's again once a person removes it."""
        run = started_run(GUID, "srv-01", now=datetime.now().replace(microsecond=0) - timedelta(minutes=5))
        root = _root(event_time=datetime.now())
        ALERT(root)
        analyst = get_db().execute(select(User.id).where(User.username == "unittest")).scalar_one()

        associate(run.uuid, root.uuid, analyst, "unittest")
        evaluation = evaluate(root, datetime.now())
        assert evaluation.maintenance is None
        assert {row.run_id for row in evaluation.existing if not row.removed} == {run.id}

        disassociate(run.uuid, root.uuid, analyst, "unittest")
        assert evaluate(root, datetime.now()).maintenance.uuid == window.uuid

    def test_a_window_ended_early_ends_there(self, window):
        ended = datetime.now().replace(microsecond=0) - timedelta(minutes=5)
        maintenance.end_window("win10-01", LAUNCHER, now=ended)
        before = ended - timedelta(minutes=1)
        assert evaluate(_root(event_time=before), before).maintenance.uuid == window.uuid
        # before its planned end, after it was ended
        assert evaluate(_root(event_time=datetime.now()), datetime.now()).maintenance is None

    def test_the_gate_stays_open_for_a_windows_late_alerts(self):
        extra = timedelta(hours=get_config().svs.runs.attribution_extra_hours)
        opened = datetime.now().replace(microsecond=0) - extra - timedelta(hours=1)
        maintenance.open_window("win10-01", 30, "staging", LAUNCHER, now=opened)
        # ended early: the horizon runs from when it ended, not from its planned end
        ended = opened + timedelta(minutes=10)
        maintenance.end_window("win10-01", LAUNCHER, now=ended)
        assert attribution_open(ended + extra - timedelta(minutes=1))
        attribution.clear_caches()
        assert not attribution_open(ended + extra + timedelta(minutes=1))


#
# grouped hunts (docs/SVS_RUNS.md, *Hunt suppression during runs*)
#

def _match(event_time: datetime, host: str = "win10-01") -> RootAnalysis:
    root = RootAnalysis(uuid=str(uuid.uuid4()))
    root.add_observable_by_spec(F_HOSTNAME, host)
    root.event_time = event_time
    return root


def test_a_windows_matches_are_keyed_by_the_window_and_never_recorded_for_a_run():
    """A run's late attribution window still covers the host when the window opens: the window's
    matches belong to the window for the hunter as they do for attribution."""
    started = datetime.now().replace(microsecond=0) - timedelta(hours=3)
    run = started_run(GUID, now=started)
    window = maintenance.open_window("win10-01", 30, "staging", LAUNCHER, now=datetime.now() - timedelta(minutes=10))
    inside, after = datetime.now(), datetime.now() + timedelta(hours=1)

    owners = suppression_owners([_match(inside), _match(after), _match(inside, host="srv-01")])
    assert [owner.uuid if owner else None for owner in owners] == [window.uuid, run.uuid, None]
    assert suppression_key(owners[0], "alice") == f"svs_maintenance:{window.uuid}:alice"
    assert suppression_key(owners[1], "alice") == f"svs_run:{run.uuid}:alice"

    assert record_suppressed_matches(HUNT_UUID, [(_match(inside), "alice")]) == []
    assert [r.uuid for r, _ in record_suppressed_matches(HUNT_UUID, [(_match(after), "alice")])] == [run.uuid]


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


def test_an_alert_is_confirmed_only_once_no_analysis_is_delayed():
    """A delayed module may still find a marker in it, so it is not closed before that."""
    maintenance.open_window("win10-01", 30, "staging", LAUNCHER, now=datetime.now() - timedelta(minutes=10))
    root = _root(event_time=datetime.now())
    delayed = DelayedAnalysis()
    delayed.delayed = True
    root.add_observable_by_spec(F_TEST, "sandbox").add_analysis(delayed)
    root.save()
    ALERT(root)

    sync_alert(root)
    (record,) = _records(root.uuid)
    assert record.confirmed_at is None
    assert maintenance.close_alerts() == 0

    delayed.delayed = False
    root.save()
    sync_alert(root)
    assert _records(root.uuid)[0].confirmed_at is not None
    assert maintenance.close_alerts() == 1


def test_an_alert_whose_analysis_was_aborted_is_confirmed():
    """An aborted pass abandons what was delayed, so it is the alert's last, although its analysis
    still reads delayed."""
    maintenance.open_window("win10-01", 30, "staging", LAUNCHER, now=datetime.now() - timedelta(minutes=10))
    root = _root(event_time=datetime.now())
    delayed = DelayedAnalysis()
    delayed.delayed = True
    root.add_observable_by_spec(F_TEST, "sandbox").add_analysis(delayed)
    root.save()
    ALERT(root)

    context = EngineExecutionContext(root)
    context.analysis_aborted = True
    create_test_orchestrator()._sync_alert_to_database(context)
    assert root.delayed
    assert _records(root.uuid)[0].confirmed_at is not None
    assert maintenance.close_alerts() == 1


def test_an_alert_an_analyst_associated_with_a_run_is_left_alone(caplog):
    maintenance.open_window("win10-01", 30, "staging", LAUNCHER, now=datetime.now() - timedelta(minutes=10))
    root = _root(event_time=datetime.now())
    ALERT(root)
    sync_alert(root)
    # after its correlation pass, before the timers
    attribute_to_run(root.uuid)

    caplog.set_level(logging.INFO)
    assert maintenance.close_alerts() == 0
    assert _alert(root.uuid).disposition == DISPOSITION_OPEN
    (record,) = [r for r in caplog.records if "left alone" in r.getMessage()]
    assert record.alert_uuids == [root.uuid]
    assert _records(root.uuid)[0].closed_at is not None


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
