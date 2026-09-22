"""Tests for the `ace alert` commands."""

import os
from argparse import Namespace

import pytest

from saq.analysis.root import load_root
from saq.cli.commands.alerts import delete_alerts, reload_alerts, reset_alerts
from saq.constants import ANALYSIS_MODE_CORRELATION, F_TEST
from saq.database.model import ObservableMapping, Workload
from saq.database.pool import get_db
from saq.database.util.alert import ALERT, get_alert_by_uuid
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.environment import get_base_dir
from saq.modules.test import BasicTestAnalysis
from saq.util.uuid import get_storage_dir


@pytest.mark.integration
def test_delete_removes_the_row_and_the_storage_directory(root_analysis, monkeypatch):
    deleted_from_search = []
    monkeypatch.setattr("saq.cli.commands.alerts.submit_delete_task", deleted_from_search.append)

    root_analysis.save()
    ALERT(root_analysis)
    storage_dir = os.path.join(get_base_dir(), root_analysis.storage_dir)
    assert get_alert_by_uuid(root_analysis.uuid) is not None
    assert os.path.isdir(storage_dir)

    with pytest.raises(SystemExit) as e:
        delete_alerts(Namespace(uuids=[root_analysis.uuid]))

    assert e.value.code == 0
    get_db().expire_all()
    assert get_alert_by_uuid(root_analysis.uuid) is None
    assert not os.path.exists(storage_dir)
    assert deleted_from_search == [root_analysis.uuid]


@pytest.mark.integration
def test_delete_of_an_unknown_alert_is_not_an_error(monkeypatch):
    monkeypatch.setattr("saq.cli.commands.alerts.submit_delete_task", lambda uuid: True)

    with pytest.raises(SystemExit) as e:
        delete_alerts(Namespace(uuids=["00000000-0000-4000-8000-000000000000"]))

    assert e.value.code == 0


def _mapped_observable_count(alert_id: int) -> int:
    get_db().expire_all()
    return get_db().query(ObservableMapping).filter(ObservableMapping.alert_id == alert_id).count()


@pytest.mark.integration
def test_reset_of_an_alert_clears_the_analysis_and_its_index_rows(root_analysis):
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_TEST, "test_add_file")
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("basic_test", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    storage_dir = get_storage_dir(root_analysis.uuid)
    root = load_root(storage_dir)
    assert root.get_observable(observable.uuid).get_and_load_analysis(BasicTestAnalysis)
    alert = ALERT(root)
    assert _mapped_observable_count(alert.id) > 1

    # an absolute path names the same alert as the relative one recorded in the database
    reset_alerts(Namespace(dirs=[os.path.abspath(storage_dir)]))

    root = load_root(storage_dir)
    assert len(root.all_observables) == 1
    assert root.get_observable(observable.uuid).get_and_load_analysis(BasicTestAnalysis) is None
    assert _mapped_observable_count(alert.id) == 1


@pytest.mark.integration
def test_reset_of_a_directory_that_is_not_an_alert(root_analysis):
    root_analysis.add_observable_by_spec(F_TEST, "test")
    root_analysis.state = {"key": "value"}
    root_analysis.save()

    reset_alerts(Namespace(dirs=[root_analysis.storage_dir]))

    assert not load_root(root_analysis.storage_dir).state
    assert get_alert_by_uuid(root_analysis.uuid) is None


@pytest.mark.integration
def test_analyze_schedules_the_alert_in_correlation_mode(root_analysis):
    root_analysis.save()
    ALERT(root_analysis)
    assert get_db().query(Workload).filter(Workload.uuid == root_analysis.uuid).count() == 0

    reload_alerts(Namespace(uuids=[root_analysis.uuid, "00000000-0000-4000-8000-000000000000"]))

    get_db().expire_all()
    workload = get_db().query(Workload).filter(Workload.uuid == root_analysis.uuid).one()
    assert workload.analysis_mode == ANALYSIS_MODE_CORRELATION
