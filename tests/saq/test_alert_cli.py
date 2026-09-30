"""Tests for the `ace alert` commands."""

import os
import uuid
from argparse import Namespace
from datetime import datetime, timedelta

import pytest

from saq.analysis.root import load_root
from saq.cli.alert_sweep import iter_node_alert_id_batches, run_alert_sweep
from saq.cli.commands.alerts import (
    _rebuild_alert_index,
    backfill_icons,
    delete_alerts,
    rebuild_index,
    reload_alerts,
    reset_alerts,
)
from saq.constants import ANALYSIS_MODE_CORRELATION, F_TEST
from saq.database.model import Alert, ObservableMapping, Workload
from saq.database.pool import get_db
from saq.database.util.alert import ALERT, get_alert_by_uuid
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.environment import get_base_dir
from saq.gui.icon import KEY_ICON_CONFIGURATION
from saq.modules.test import BasicTestAnalysis
from saq.util.uuid import get_storage_dir, storage_dir_from_uuid
from tests.saq.helpers import create_root_analysis


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


def _alert_inserted_days_ago(days: int, observable_value: str = None) -> str:
    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=storage_dir_from_uuid(root_uuid))
    root.initialize_storage()
    if observable_value:
        root.add_observable_by_spec(F_TEST, observable_value)
    root.save()
    ALERT(root)
    get_db().execute(Alert.__table__.update().where(Alert.uuid == root_uuid)
                     .values(insert_date=datetime.now() - timedelta(days=days)))
    get_db().commit()
    return root_uuid


def _alert_id(root_uuid: str) -> int:
    get_db().expire_all()
    return get_db().query(Alert.id).filter(Alert.uuid == root_uuid).scalar()


def _sweep_args(**overrides) -> Namespace:
    args = dict(resync_all=True, insert_date=None, after_id=0, workers=1, batch_size=100, dirs=[])
    args.update(overrides)
    return Namespace(**args)


def _run(command, **overrides) -> int:
    with pytest.raises(SystemExit) as e:
        command(_sweep_args(**overrides))

    return e.value.code


@pytest.mark.integration
def test_rebuild_all_narrowed_by_insert_date(monkeypatch):
    recent = _alert_inserted_days_ago(10)
    old = _alert_inserted_days_ago(200)
    # patched only now: ALERT() rebuilds the index of the alert it creates
    rebuilt = []
    monkeypatch.setattr(Alert, "rebuild_index", lambda self: rebuilt.append(self.uuid))

    assert _run(rebuild_index, insert_date="-90d") == 0
    assert recent in rebuilt
    assert old not in rebuilt


@pytest.mark.integration
@pytest.mark.parametrize("overrides", [
    dict(resync_all=False, insert_date="-90d"),   # narrows --all, meaningless without it
    dict(resync_all=True, insert_date="-90dd"),   # not a date range
    dict(resync_all=False, after_id=1),           # narrows --all, meaningless without it
    dict(workers=0),
    dict(batch_size=0),
])
def test_rebuild_rejects_bad_arguments(overrides, monkeypatch):
    _alert_inserted_days_ago(1)
    rebuilt = []
    monkeypatch.setattr(Alert, "rebuild_index", lambda self: rebuilt.append(self.uuid))

    assert _run(rebuild_index, **overrides) == 1
    assert rebuilt == []


@pytest.mark.integration
def test_rebuild_all_pages_through_every_alert(monkeypatch):
    uuids = [_alert_inserted_days_ago(1) for _ in range(3)]
    rebuilt = []
    monkeypatch.setattr(Alert, "rebuild_index", lambda self: rebuilt.append(self.uuid))

    # one alert per page: every page boundary is crossed
    assert _run(rebuild_index, batch_size=1) == 0
    assert rebuilt == uuids


@pytest.mark.integration
def test_rebuild_all_resumes_after_an_id(monkeypatch):
    first, second, third = [_alert_inserted_days_ago(1) for _ in range(3)]
    rebuilt = []
    monkeypatch.setattr(Alert, "rebuild_index", lambda self: rebuilt.append(self.uuid))

    assert _run(rebuild_index, after_id=_alert_id(first), batch_size=1) == 0
    assert rebuilt == [second, third]


@pytest.mark.integration
def test_rebuild_all_skips_alerts_of_other_nodes(monkeypatch):
    local = _alert_inserted_days_ago(1)
    remote = _alert_inserted_days_ago(1)
    get_db().execute(Alert.__table__.update().where(Alert.uuid == remote).values(location="some-other-node"))
    get_db().commit()
    rebuilt = []
    monkeypatch.setattr(Alert, "rebuild_index", lambda self: rebuilt.append(self.uuid))

    assert _run(rebuild_index) == 0
    assert rebuilt == [local]


@pytest.mark.integration
def test_rebuild_failure_does_not_stop_the_run(monkeypatch):
    broken, healthy = _alert_inserted_days_ago(1), _alert_inserted_days_ago(1)
    rebuilt = []

    def _rebuild_index(self):
        if self.uuid == broken:
            raise RuntimeError("broken")

        rebuilt.append(self.uuid)

    monkeypatch.setattr(Alert, "rebuild_index", _rebuild_index)

    assert _run(rebuild_index, batch_size=1) == 1
    assert rebuilt == [healthy]


@pytest.mark.integration
def test_rebuild_of_a_missing_directory_fails(monkeypatch):
    root_uuid = _alert_inserted_days_ago(1)
    rebuilt = []
    monkeypatch.setattr(Alert, "rebuild_index", lambda self: rebuilt.append(self.uuid))

    assert _run(rebuild_index, resync_all=False, dirs=[storage_dir_from_uuid(root_uuid), "does/not/exist"]) == 1
    assert rebuilt == [root_uuid]


@pytest.mark.integration
def test_rebuild_all_with_workers_restores_the_index():
    alert_ids = [_alert_id(_alert_inserted_days_ago(1, observable_value=f"value_{i}")) for i in range(3)]
    for alert_id in alert_ids:
        assert _mapped_observable_count(alert_id) == 1

    get_db().execute(ObservableMapping.__table__.delete().where(ObservableMapping.alert_id.in_(alert_ids)))
    get_db().commit()
    assert all(_mapped_observable_count(alert_id) == 0 for alert_id in alert_ids)

    assert _run(rebuild_index, workers=2, batch_size=1) == 0
    assert all(_mapped_observable_count(alert_id) == 1 for alert_id in alert_ids)


@pytest.mark.integration
def test_backfill_icons_all():
    root_uuid = str(uuid.uuid4())
    root = create_root_analysis(uuid=root_uuid, storage_dir=storage_dir_from_uuid(root_uuid))
    root.initialize_storage()
    root.set_extension(KEY_ICON_CONFIGURATION, {"url": "https://example.com/icon.png"})
    root.save()
    ALERT(root)
    get_db().execute(Alert.__table__.update().where(Alert.uuid == root_uuid).values(icon_url=None))
    get_db().commit()

    assert _run(backfill_icons) == 0

    get_db().expire_all()
    assert get_db().query(Alert.icon_url).filter(Alert.uuid == root_uuid).scalar() == "https://example.com/icon.png"


@pytest.mark.integration
def test_interrupted_sweep_reports_where_to_resume(monkeypatch):
    first, second, third = [_alert_inserted_days_ago(1) for _ in range(3)]
    rebuilt = []

    def _rebuild_index(self):
        if self.uuid == third:
            raise KeyboardInterrupt()

        rebuilt.append(self.uuid)

    monkeypatch.setattr(Alert, "rebuild_index", _rebuild_index)

    result = run_alert_sweep(iter_node_alert_id_batches(batch_size=1), _rebuild_alert_index, total=3, after_id=0)

    assert not result.completed
    assert rebuilt == [first, second]
    # everything at or below the resume point is done; the interrupted alert is not
    assert result.resume_after_id == _alert_id(second)

    resumed = []
    monkeypatch.setattr(Alert, "rebuild_index", lambda self: resumed.append(self.uuid))
    assert _run(rebuild_index, after_id=result.resume_after_id) == 0
    assert resumed == [third]
