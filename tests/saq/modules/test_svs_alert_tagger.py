"""The svs_alert_tagger module (saq.modules.svs.SVSAlertTagger): the svs_test and
svs:marker_mismatch tags and the mismatch detection (docs/SVS_RUNS.md, *Attribution*)."""

import uuid
from datetime import datetime, timedelta

import pytest

from saq.alert_routing import reset_alert_routers
from saq.analysis.root import RootAnalysis
from saq.configuration.config import get_analysis_module_config
from saq.constants import F_HOSTNAME, F_TEST
from saq.database.util.alert import ALERT
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.engine_configuration import EngineConfiguration
from saq.filesystem.adapter import FileSystemAdapter
from saq.modules.context import AnalysisModuleContext
from saq.modules.svs import SVSAlertTagger
from saq.signatures.builtin import SVS_MARKER_MISMATCH
from saq.svs import attribution, windows
from saq.svs.constants import TAG_MARKER_MISMATCH, TAG_SVS_TEST
from tests.saq.helpers import create_root_analysis
from tests.saq.svs.conftest import add_catalog_test, add_test_host, started_run

pytestmark = pytest.mark.integration

GUID = "aaaaaaaa-1111-4111-8111-111111111111"


@pytest.fixture(autouse=True)
def setup(monkeypatch):
    monkeypatch.setattr(windows, "hunt_info", lambda: {})
    attribution.clear_caches()
    reset_alert_routers()
    monkeypatch.setattr("saq.database.util.alert.submit_payload_task", lambda alert_uuid: None)
    add_catalog_test(GUID)
    add_test_host("win10-01")
    yield
    attribution.clear_caches()
    reset_alert_routers()


@pytest.fixture
def run():
    return started_run(GUID, now=datetime.now() - timedelta(minutes=1))


def _alert(host: str, marker: str) -> RootAnalysis:
    root = create_root_analysis(uuid=str(uuid.uuid4()), event_time=datetime.now(), analysis_mode="correlation")
    root.initialize_storage()
    root.add_observable_by_spec(F_HOSTNAME, host)
    root.details = {"events": [{"command_line": f"whoami & REM {marker}"}]}
    root.add_detection_point("hunt hit")
    root.save()
    ALERT(root)
    return root


def _tag(root: RootAnalysis):
    # the engine hands modules the root itself, not an adapter
    context = AnalysisModuleContext(
        delayed_analysis_interface=None, configuration_manager=ConfigurationManager(config=EngineConfiguration()),
        root=root, filesystem=FileSystemAdapter(), state_repository=None)
    SVSAlertTagger(context=context, config=get_analysis_module_config("svs_alert_tagger")).execute_post_analysis()


def _mismatch_detections(root: RootAnalysis):
    return [dp for dp in root.detections if dp.signature_uuid == SVS_MARKER_MISMATCH.uuid]


def test_a_mismatch_is_tagged_and_detected_once(run):
    root = _alert("srv-01", run.marker)

    _tag(root)
    _tag(root)

    assert root.has_tag(TAG_MARKER_MISMATCH)
    assert not root.has_tag(TAG_SVS_TEST)
    (detection,) = _mismatch_detections(root)
    assert detection.details == {"marker": run.marker, "result": "other host"}
    assert run.marker in detection.description


def test_an_unknown_marker_while_a_run_is_open(run):
    marker = "svs-" + "q" * 26
    root = _alert("win10-01", marker)
    _tag(root)
    (detection,) = _mismatch_detections(root)
    assert detection.details["result"] == "unknown"


def test_a_routed_alert_is_tagged_svs_test_until_it_is_not(run):
    root = _alert("win10-01", run.marker)
    _tag(root)
    assert root.has_tag(TAG_SVS_TEST)
    assert not _mismatch_detections(root)

    # the marker moves from the alert's details (the root's branch, which reaches every detection)
    # to one observable, and another branch gets a detection: no longer fully attributed
    root.details = {}
    marked = root.add_observable_by_spec(F_TEST, f"ran {run.marker}")
    marked.add_detection_point("test detection")
    other = root.add_observable_by_spec(F_TEST, "unrelated")
    other.add_detection_point("real detection")
    root.detections.clear()
    _tag(root)
    assert not root.has_tag(TAG_SVS_TEST)


def test_nothing_without_an_alert_row(run):
    root = create_root_analysis(uuid=str(uuid.uuid4()), event_time=datetime.now())
    root.initialize_storage()
    root.add_observable_by_spec(F_HOSTNAME, "srv-01")
    root.details = {"cmd": run.marker}
    _tag(root)
    assert not root.has_tag(TAG_MARKER_MISMATCH)


def test_nothing_while_no_run_is_open():
    root = _alert("srv-01", "svs-" + "q" * 26)
    _tag(root)
    assert not root.has_tag(TAG_MARKER_MISMATCH)
    assert not _mismatch_detections(root)
