"""The SVS marker router (saq.svs.routing, docs/SVS_RUNS.md, *Attribution*) in use: ALERT() at
PRE_INSERT, and the engine's POST_ANALYSIS stage."""

import logging
import uuid
from datetime import datetime, timedelta
from unittest.mock import Mock

import pytest
from sqlalchemy import select

from saq.alert_routing import get_alert_routers, load_alert_routers, reset_alert_routers
from saq.analysis.root import RootAnalysis, load_root
from saq.configuration.config import get_config, get_service_config
from saq.constants import (
    ANALYSIS_MODE_CORRELATION,
    ANALYSIS_MODULE_YARA_SCANNER_V3_4,
    F_HOSTNAME,
    F_TEST,
    QUEUE_DEFAULT,
    SERVICE_YARA_SCANNER,
    EventTimeSource,
)
from saq.database.model import Alert, AlertQueueChange, SVSAttribution, User
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.database.util.alert import ALERT
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.svs import maintenance, routing
from saq.svs.attribution import saved_sightings
from saq.svs.constants import ScanPoint
from saq.svs.refusals import Caller, refuse
from saq.util.uuid import get_storage_dir
from saq.yara_scanning import client as yara_client
from saq.yara_scanning.client import YaraServiceUnavailable
from tests.saq.helpers import create_root_analysis
from tests.saq.svs.conftest import add_catalog_test, add_test_host, started_run, sync_alert

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"
CALLER = Caller(name="art-launcher", address="10.1.2.3")


@pytest.fixture(autouse=True)
def setup(no_hunts):
    reset_alert_routers()
    add_catalog_test(GUID)
    add_test_host("win10-01")
    yield
    reset_alert_routers()


@pytest.fixture
def run():
    return started_run(GUID)


def _root(*, marker=None, host="win10-01", analysis_mode=None, queue=None) -> RootAnalysis:
    root = create_root_analysis(uuid=str(uuid.uuid4()), event_time=datetime.now() + timedelta(minutes=1),
                                analysis_mode=analysis_mode, queue=queue)
    root.initialize_storage()
    root.add_observable_by_spec(F_HOSTNAME, host)
    if marker:
        root.details = {"events": [{"command_line": f"whoami & REM {marker}"}]}
    root.add_detection_point("hunt hit")
    root.save()
    return root


def _queue(alert_uuid: str) -> str:
    get_db().commit()
    return get_db().query(Alert.queue).filter(Alert.uuid == alert_uuid).scalar()


def _changes(alert_uuid: str) -> list[tuple]:
    get_db().commit()
    return [tuple(row) for row in get_db().execute(
        select(AlertQueueChange.from_queue, AlertQueueChange.to_queue, AlertQueueChange.router)
        .join(Alert, Alert.id == AlertQueueChange.alert_id).where(Alert.uuid == alert_uuid)
        .order_by(AlertQueueChange.id))]


def _attributions(alert_uuid: str) -> list[tuple]:
    with private_transaction() as session:
        return [(row.confidence, row.removed_at is not None) for row in session.execute(
            select(SVSAttribution).where(SVSAttribution.alert_uuid == alert_uuid).order_by(SVSAttribution.id))
            .scalars()]


def test_the_router_is_configured_ahead_of_the_detection_queue_router():
    load_alert_routers()
    names = [router.name for router in get_alert_routers()]
    assert names.index("svs_marker") < names.index("detection_queue")


class TestFallbackEventTime:
    def test_a_hunt_that_fell_back_on_a_test_host_is_warned_about_once(self, run, caplog):
        run_uuid = run.uuid
        root = _root()
        root.set_event_time(root.event_time, EventTimeSource.QUERY_TIME)
        root.description = "suspicious powershell"
        root.save()
        caplog.set_level(logging.INFO)
        ALERT(root)
        sync_alert(root)

        with private_transaction() as session:
            assert session.execute(select(SVSAttribution.event_time_source).where(
                SVSAttribution.alert_uuid == root.uuid)).scalars().all() == ["query_time"]
        (warning,) = [r for r in caplog.records if "without the event's own time" in r.getMessage()]
        assert warning.levelno == logging.WARNING
        assert (warning.hunt, warning.alert_uuid, warning.svs_run, warning.stage) == (
            "suspicious powershell", root.uuid, run_uuid, "pre_insert")

    def test_a_hunt_first_attributed_by_a_later_pass_is_warned_about_then(self, run, caplog):
        run_uuid = run.uuid
        # as inserted, it names no host, so nothing concerns a run
        root = create_root_analysis(uuid=str(uuid.uuid4()), event_time=datetime.now() + timedelta(minutes=1))
        root.initialize_storage()
        root.add_detection_point("hunt hit")
        root.set_event_time(root.event_time, EventTimeSource.QUERY_TIME)
        root.save()
        caplog.set_level(logging.INFO)
        ALERT(root)
        assert _attributions(root.uuid) == []
        assert not [r for r in caplog.records if "without the event's own time" in r.getMessage()]

        # analysis finds the test host
        root.add_observable_by_spec(F_HOSTNAME, "win10-01")
        root.save()
        sync_alert(root)
        assert _attributions(root.uuid) == [("context", False)]
        (warning,) = [r for r in caplog.records if "without the event's own time" in r.getMessage()]
        assert (warning.alert_uuid, warning.svs_run, warning.stage) == (root.uuid, run_uuid, "post_analysis")

    def test_a_later_pass_that_changes_its_attributions_is_not_warned_about_again(self, run, caplog):
        root = _root()
        root.set_event_time(root.event_time, EventTimeSource.QUERY_TIME)
        root.save()
        caplog.set_level(logging.INFO)
        ALERT(root)
        assert _attributions(root.uuid) == [("context", False)]

        # analysis finds the run's marker, which updates the attribution
        root.details = {"events": [{"command_line": f"whoami & REM {run.marker}"}]}
        root.save()
        sync_alert(root)
        assert _attributions(root.uuid) == [("marker", False)]
        (warning,) = [r for r in caplog.records if "without the event's own time" in r.getMessage()]
        assert warning.stage == "pre_insert"

    def test_a_hunt_inside_a_maintenance_window_is_warned_about(self, caplog):
        maintenance.open_window("win10-01", 30, "staging", CALLER, now=datetime.now() - timedelta(minutes=10))
        root = _root()
        root.set_event_time(root.event_time, EventTimeSource.QUERY_TIME)
        root.description = "suspicious powershell"
        root.save()
        caplog.set_level(logging.INFO)
        ALERT(root)
        sync_alert(root)

        assert _attributions(root.uuid) == []
        (warning,) = [r for r in caplog.records if "without the event's own time" in r.getMessage()]
        assert (warning.levelno, warning.hunt, warning.alert_uuid, warning.stage) == (
            logging.WARNING, "suspicious powershell", root.uuid, "pre_insert")

    @pytest.mark.usefixtures("overlapping_runs")
    def test_a_hunt_that_several_runs_could_claim_is_warned_about(self, caplog):
        started_run(GUID)
        started_run(GUID)
        root = _root()
        root.set_event_time(root.event_time, EventTimeSource.QUERY_TIME)
        root.description = "suspicious powershell"
        root.save()
        caplog.set_level(logging.INFO)
        ALERT(root)

        assert _attributions(root.uuid) == []
        assert [r for r in caplog.records if "context attribution of alert" in r.getMessage()]
        (warning,) = [r for r in caplog.records if "without the event's own time" in r.getMessage()]
        assert (warning.levelno, warning.hunt, warning.alert_uuid, warning.stage) == (
            logging.WARNING, "suspicious powershell", root.uuid, "pre_insert")

    def test_the_events_own_time_is_not_warned_about(self, run, caplog):
        root = _root()
        caplog.set_level(logging.INFO)
        ALERT(root)
        assert not [r for r in caplog.records if "without the event's own time" in r.getMessage()]
        with private_transaction() as session:
            assert session.execute(select(SVSAttribution.event_time_source).where(
                SVSAttribution.alert_uuid == root.uuid)).scalars().all() == ["event"]


class TestPreInsert:
    def test_a_marker_that_agrees_routes_the_alert(self, run):
        root = _root(marker=run.marker)
        ALERT(root)

        assert _queue(root.uuid) == get_config().svs.queue
        assert load_root(root.storage_dir).queue == get_config().svs.queue
        assert _changes(root.uuid) == [(QUEUE_DEFAULT, get_config().svs.queue, "svs_marker")]
        assert _attributions(root.uuid) == [("marker", False)]

    def test_it_wins_over_a_detection_queue(self, run):
        root = _root(marker=run.marker)
        root.add_detection_point("yara rule with a queue meta", queue="experimental")
        root.save()
        ALERT(root)
        assert _queue(root.uuid) == get_config().svs.queue

    def test_it_overrides_a_configured_queue(self, run):
        root = _root(marker=run.marker, queue="hunting")
        ALERT(root)
        assert _queue(root.uuid) == get_config().svs.queue

    def test_partial_stays_in_its_queue(self, run):
        root = _root()
        parent = root.add_observable_by_spec(F_TEST, f"run {run.marker}")
        parent.add_detection_point("test detection")
        other = root.add_observable_by_spec(F_TEST, "unrelated")
        other.add_detection_point("real detection")
        root.save()

        ALERT(root)
        assert _queue(root.uuid) == QUEUE_DEFAULT
        # the marker's branch: its own detection and the root's
        assert _attributions(root.uuid) == [("marker", False), ("marker", False)]

    def test_a_mismatch_stays_and_attributes_nothing(self, run):
        root = _root(marker=run.marker, host="srv-01")
        ALERT(root)
        assert _queue(root.uuid) == QUEUE_DEFAULT
        assert _attributions(root.uuid) == []

    def test_context(self, run):
        root = _root()
        ALERT(root)
        assert _queue(root.uuid) == get_config().svs.queue
        assert _attributions(root.uuid) == [("context", False)]

    def test_a_refused_registration_on_a_test_host_stays_in_triage(self):
        # its alert names the host of the live run, which context attribution would claim it for
        started_run(GUID, now=datetime.now() - timedelta(minutes=1))
        alert_uuid = refuse(CALLER, "win10-01", "CORP\\mallory", "mallory is not a user of win10-01",
                            launcher="art", test_guid=GUID, payload={})
        assert _queue(alert_uuid) == QUEUE_DEFAULT
        assert _attributions(alert_uuid) == []

    def test_nothing_happens_without_runs(self):
        root = _root(marker="svs-" + "a" * 26)
        ALERT(root)
        assert _queue(root.uuid) == QUEUE_DEFAULT
        assert _attributions(root.uuid) == []

    def test_a_failing_router_never_breaks_the_insert(self, run, monkeypatch):
        monkeypatch.setattr("saq.error.reporting.write_error_report", lambda *a, **k: None)
        monkeypatch.setattr(routing, "evaluate", Mock(side_effect=RuntimeError("broken")))
        root = _root(marker=run.marker)
        ALERT(root)
        assert _queue(root.uuid) == QUEUE_DEFAULT


class TestPostAnalysis:
    def _hunt_alert(self, run):
        """A hunt alert inserted before analysis: nothing in it names a test host yet."""
        root = _root(analysis_mode=ANALYSIS_MODE_CORRELATION, host="srv-01")
        ALERT(root)
        assert _queue(root.uuid) == QUEUE_DEFAULT
        return root

    def test_a_marker_found_by_analysis_moves_the_alert(self, run):
        root = self._hunt_alert(run)
        # analysis decoded a command line on the target
        root.add_observable_by_spec(F_HOSTNAME, "win10-01")
        root.add_observable_by_spec(F_TEST, f"decoded {run.marker}")
        sync_alert(root)

        assert _queue(root.uuid) == get_config().svs.queue
        assert _changes(root.uuid)[-1] == (QUEUE_DEFAULT, get_config().svs.queue, "svs_marker")

    def test_it_goes_back_when_it_is_no_longer_fully_attributed(self, run):
        root = self._hunt_alert(run)
        root.add_observable_by_spec(F_HOSTNAME, "win10-01")
        root.add_observable_by_spec(F_TEST, f"decoded {run.marker}")
        sync_alert(root)
        assert _queue(root.uuid) == get_config().svs.queue

        # a later pass finds a detection on another branch
        other = root.add_observable_by_spec(F_TEST, "unrelated")
        other.add_detection_point("real detection")
        sync_alert(root)

        assert _queue(root.uuid) == QUEUE_DEFAULT
        assert _changes(root.uuid)[-1] == (get_config().svs.queue, QUEUE_DEFAULT, "svs_marker")

    def test_an_alert_an_analyst_owns_is_not_moved(self, run, caplog):
        root = self._hunt_alert(run)
        user = get_db().query(User).filter(User.username == "unittest").one()
        get_db().execute(Alert.__table__.update().where(Alert.uuid == root.uuid).values(owner_id=user.id))
        get_db().commit()

        root.add_observable_by_spec(F_HOSTNAME, "win10-01")
        root.add_observable_by_spec(F_TEST, f"decoded {run.marker}")
        sync_alert(root)

        assert _queue(root.uuid) == QUEUE_DEFAULT
        # attributed all the same: the alert gets its SVS status
        assert _attributions(root.uuid) == [("marker", False)]
        assert any(getattr(r, "decision", None) == "not moved because owned" for r in caplog.records)


class TestEngine:
    def test_a_marker_in_a_dropped_file_routes_the_alert(self, monkeypatch, tmp_path, root_analysis):
        """The marker rule matches the file, the executor saves the match from the YARA analysis's
        details, and the alert the engine converts is routed at PRE_INSERT (FR-19, FR-20)."""
        signature_dir = tmp_path / "yara"
        signature_dir.mkdir()
        monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "signature_dir", str(signature_dir))

        def unavailable(path, meta_tags=None, qa=None):
            raise YaraServiceUnavailable("connection refused")

        monkeypatch.setattr(yara_client, "scan_file", unavailable)
        run = started_run(GUID, now=datetime.now() - timedelta(minutes=1))

        file_path = root_analysis.create_file_path("dropped.ps1")
        with open(file_path, "wb") as fp:
            fp.write(f"Write-Host 'hello' <# {run.marker} #>".encode("utf-16-le"))

        root_analysis.analysis_mode = "test_groups"
        root_analysis.add_observable_by_spec(F_HOSTNAME, "win10-01")
        root_analysis.add_file_observable(file_path)
        root_analysis.add_detection_point("hunt hit")
        root_analysis.save()
        root_analysis.schedule()

        engine = Engine()
        engine.configuration_manager.enable_module(ANALYSIS_MODULE_YARA_SCANNER_V3_4, "test_groups")
        engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

        root = load_root(get_storage_dir(root_analysis.uuid))
        assert [s.scan_point for s in saved_sightings(root)] == [ScanPoint.FILE_CONTENTS]
        assert _queue(root.uuid) == get_config().svs.queue
        assert _attributions(root.uuid) == [("marker", False)]
