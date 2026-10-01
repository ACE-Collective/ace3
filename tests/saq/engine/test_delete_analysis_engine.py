"""End-to-end stress tests for Observable.delete_analysis driven by the REAL analysis
engine (no mocking of analysis). Each test runs the engine to produce a genuine analysis
tree, deletes an analysis, and asserts the tree/DB are cleaned up and remain consistent."""

import os
import uuid

import pytest

from saq.analysis.root import RootAnalysis, load_root
from saq.constants import F_TEST
from saq.database import db_DetectionPoint
from saq.database.model import load_alert
from saq.database.pool import get_db
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.test import BasicTestAnalysis
from saq.observables.file import FileObservable
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import validate_tree_integrity


def _run_basic_test_engine(value: str) -> RootAnalysis:
    """schedule a single F_TEST observable and run only the basic_test module to
    completion. returns the freshly loaded RootAnalysis."""
    root = create_root_for(value)
    engine = Engine()
    engine.configuration_manager.enable_module("basic_test")
    engine.start_single_threaded(
        analysis_priority_mode="test_single", execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    return load_root(get_storage_dir(root.uuid))


def create_root_for(value: str) -> RootAnalysis:
    from tests.saq.helpers import create_root_analysis

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode="test_single")
    root.initialize_storage()
    root.add_observable_by_spec(F_TEST, value)
    root.save()
    root.schedule()
    return root


def _rows_for(alert_id):
    return get_db().query(db_DetectionPoint).filter(db_DetectionPoint.alert_id == alert_id).all()


@pytest.mark.integration
def test_engine_delete_analysis_prunes_generated_child_observables():
    """basic_test on 'test_6' generates two child observables; deleting the analysis
    prunes them and leaves a healthy tree that round-trips through save/load."""
    root = _run_basic_test_engine("test_6")

    obs = root.get_observable_by_spec(F_TEST, "test_6")
    analysis = obs.get_and_load_analysis(BasicTestAnalysis)
    assert isinstance(analysis, BasicTestAnalysis)

    result_1 = root.get_observable_by_spec(F_TEST, "result_1")
    result_2 = root.get_observable_by_spec(F_TEST, "result_2")
    assert result_1 is not None and result_2 is not None
    assert validate_tree_integrity(root) == []

    obs.delete_analysis(analysis)

    assert obs.get_analysis(BasicTestAnalysis) is None
    registry = root.analysis_tree_manager.observable_registry
    assert result_1.uuid not in registry
    assert result_2.uuid not in registry
    assert validate_tree_integrity(root) == []

    root.save()
    reloaded = load_root(get_storage_dir(root.uuid))
    assert validate_tree_integrity(reloaded) == []
    assert reloaded.get_observable(obs.uuid).get_analysis(BasicTestAnalysis) is None
    assert reloaded.get_observable_by_spec(F_TEST, "result_1") is None


@pytest.mark.integration
def test_engine_delete_analysis_removes_generated_files_from_disk():
    """basic_test on 'test_add_file' writes two file observables to storage; deleting the
    analysis removes both observables and deletes their backing files."""
    root = _run_basic_test_engine("test_add_file")

    obs = root.get_observable_by_spec(F_TEST, "test_add_file")
    analysis = obs.get_and_load_analysis(BasicTestAnalysis)
    assert isinstance(analysis, BasicTestAnalysis)

    file_observables = [o for o in analysis.observables if isinstance(o, FileObservable)]
    assert len(file_observables) == 2
    full_paths = [f.full_path for f in file_observables]
    assert all(os.path.exists(p) for p in full_paths)

    obs.delete_analysis(analysis)

    registry = root.analysis_tree_manager.observable_registry
    for f in file_observables:
        assert f.uuid not in registry
    assert all(not os.path.exists(p) for p in full_paths)
    assert validate_tree_integrity(root) == []

    root.save()
    assert validate_tree_integrity(load_root(get_storage_dir(root.uuid))) == []


@pytest.mark.integration
def test_engine_delete_analysis_reconciles_detection_points_in_db():
    """basic_test on 'test_detection' raises a detection; once the alert is synced the
    detection_points row exists, and deleting the analysis + re-syncing removes it."""
    root = _run_basic_test_engine("test_detection")
    assert len(root.all_detection_points) == 1

    # the engine auto-alerts on a detection and syncs the detection_points row
    alert = load_alert(root.uuid)
    assert alert is not None
    assert len(_rows_for(alert.id)) == 1
    assert alert.detection_count == 1

    obs = alert.root_analysis.get_observable_by_spec(F_TEST, "test_detection")
    analysis = obs.get_analysis(BasicTestAnalysis)
    assert analysis is not None

    obs.delete_analysis(analysis)
    alert.sync()

    assert _rows_for(alert.id) == []
    get_db().expire_all()
    assert load_alert(root.uuid).detection_count == 0
    assert validate_tree_integrity(alert.root_analysis) == []


@pytest.mark.integration
def test_engine_delete_clears_detection_path_and_reconcile_is_idempotent():
    """after the engine raises a detection, deleting the owning analysis takes the
    observable off the detection path and reconciles the DB to zero; a second sync is a
    stable no-op (the reconcile does not thrash rows)."""
    root = _run_basic_test_engine("test_detection")
    uuid_ = root.uuid

    alert = load_alert(uuid_)
    assert alert is not None
    obs = alert.root_analysis.get_observable_by_spec(F_TEST, "test_detection")
    analysis = obs.get_analysis(BasicTestAnalysis)
    assert analysis.is_on_detection_path()  # the analysis carries the detection
    assert len(_rows_for(alert.id)) == 1

    obs.delete_analysis(analysis)

    # the detection is gone from the tree entirely
    assert alert.root_analysis.all_detection_points == []
    assert not alert.root_analysis.has_detections()
    assert validate_tree_integrity(alert.root_analysis) == []

    alert.root_analysis.save()
    alert.sync()
    assert _rows_for(alert.id) == []

    # syncing again must remain at zero (idempotent reconcile, no resurrected rows)
    alert.sync()
    assert _rows_for(alert.id) == []
    get_db().expire_all()
    assert load_alert(uuid_).detection_count == 0


@pytest.mark.integration
def test_engine_delete_analysis_with_runtime_dependency():
    """test_wait_a depends on test_wait_b at runtime (a real AnalysisDependency is
    recorded). deleting the dependent analysis keeps the tree consistent and round-trips
    through save/load without dangling references."""
    from saq.modules.test import WaitAnalysis_A, WaitAnalysis_B
    from tests.saq.helpers import create_root_analysis

    root = create_root_analysis(uuid=str(uuid.uuid4()), analysis_mode="test_groups")
    root.initialize_storage()
    root.add_observable_by_spec(F_TEST, "test_1")
    root.save()
    root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("test_wait_a", "test_groups")
    engine.configuration_manager.enable_module("test_wait_b", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root.uuid))
    obs = root.get_observable_by_spec(F_TEST, "test_1")
    assert obs.get_and_load_analysis(WaitAnalysis_A) is not None
    assert obs.get_and_load_analysis(WaitAnalysis_B) is not None
    assert validate_tree_integrity(root) == []

    # delete the dependent (source) analysis; the depended-on analysis must remain
    obs.delete_analysis(obs.get_analysis(WaitAnalysis_A))
    assert obs.get_analysis(WaitAnalysis_A) is None
    assert obs.get_analysis(WaitAnalysis_B) is not None
    assert validate_tree_integrity(root) == []

    root.save()
    reloaded = load_root(get_storage_dir(root.uuid))
    assert validate_tree_integrity(reloaded) == []
    reloaded_obs = reloaded.get_observable(obs.uuid)
    assert reloaded_obs.get_analysis(WaitAnalysis_A) is None
    assert reloaded_obs.get_and_load_analysis(WaitAnalysis_B) is not None
