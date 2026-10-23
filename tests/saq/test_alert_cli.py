"""Tests for the `ace alert` commands."""

import os
import uuid
from argparse import Namespace
from datetime import datetime, timedelta

import pytest
import pytz

from saq.analysis.root import RootAnalysis, load_root
from saq.cli.alert_sweep import iter_node_alert_id_batches, run_alert_sweep
from saq.cli.cli_main import get_cli_parser
from saq.cli.commands.alerts import (
    _rebuild_alert_index,
    backfill_icons,
    delete_alerts,
    rebuild_index,
    reload_alerts,
    reset_alerts,
)
from saq.configuration import get_config
from saq.constants import ANALYSIS_MODE_CORRELATION, F_FILE, F_IPV4, F_TEST
from saq.database.model import Alert, Lock, ObservableMapping, Workload
from saq.database.pool import get_db
from saq.database.util.alert import ALERT, get_alert_by_uuid
from saq.database.util.locking import acquire_lock
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.environment import get_base_dir, get_global_runtime_settings
from saq.gui.icon import KEY_ICON_CONFIGURATION
from saq.modules.test import BasicTestAnalysis
from saq.util.uuid import get_storage_dir, storage_dir_from_uuid
from tests.saq.helpers import create_root_analysis, make_simulated, workload_count


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


@pytest.mark.integration
def test_reset_refuses_a_simulated_alert(root_analysis, caplog):
    """A SIMULATED alert is never reset (docs/SVS_RUNS.md); the other directories still are."""
    root_analysis.add_observable_by_spec(F_TEST, "test")
    root_analysis.state = {"key": "value"}
    root_analysis.save()
    alert = ALERT(root_analysis)
    make_simulated(alert)
    storage_dir = get_storage_dir(root_analysis.uuid)

    reset_alerts(Namespace(dirs=[storage_dir]))

    assert load_root(storage_dir).state == {"key": "value"}
    assert f"alert {alert.uuid} is SIMULATED" in caplog.text


@pytest.mark.integration
def test_analyze_refuses_a_simulated_alert(root_analysis, caplog):
    root_analysis.save()
    alert = ALERT(root_analysis)
    make_simulated(alert)

    reload_alerts(Namespace(uuids=[alert.uuid]))

    assert workload_count(alert.uuid) == 0
    assert f"alert {alert.uuid} is SIMULATED" in caplog.text


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


def _record_rebuilds(monkeypatch) -> list[str]:
    """The uuids of the alerts the sweep rebuilds, in order; each is still rebuilt for real."""
    rebuilt = []
    original = Alert.rebuild_index

    def _rebuild_index(self):
        rebuilt.append(self.uuid)
        return original(self)

    monkeypatch.setattr(Alert, "rebuild_index", _rebuild_index)
    return rebuilt


@pytest.mark.integration
def test_rebuild_all_narrowed_by_insert_date(monkeypatch):
    recent = _alert_inserted_days_ago(10)
    old = _alert_inserted_days_ago(200)
    # patched only now: ALERT() rebuilds the index of the alert it creates
    rebuilt = _record_rebuilds(monkeypatch)

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
    rebuilt = _record_rebuilds(monkeypatch)

    assert _run(rebuild_index, **overrides) == 1
    assert rebuilt == []


@pytest.mark.integration
def test_rebuild_all_pages_through_every_alert(monkeypatch):
    uuids = [_alert_inserted_days_ago(1) for _ in range(3)]
    rebuilt = _record_rebuilds(monkeypatch)

    # one alert per page: every page boundary is crossed
    assert _run(rebuild_index, batch_size=1) == 0
    assert rebuilt == uuids


@pytest.mark.integration
def test_rebuild_all_resumes_after_an_id(monkeypatch):
    first, second, third = [_alert_inserted_days_ago(1) for _ in range(3)]
    rebuilt = _record_rebuilds(monkeypatch)

    assert _run(rebuild_index, after_id=_alert_id(first), batch_size=1) == 0
    assert rebuilt == [second, third]


@pytest.mark.integration
def test_rebuild_all_skips_alerts_of_other_nodes(monkeypatch):
    local = _alert_inserted_days_ago(1)
    remote = _alert_inserted_days_ago(1)
    get_db().execute(Alert.__table__.update().where(Alert.uuid == remote).values(location="some-other-node"))
    get_db().commit()
    rebuilt = _record_rebuilds(monkeypatch)

    assert _run(rebuild_index) == 0
    assert rebuilt == [local]


@pytest.mark.integration
def test_rebuild_failure_does_not_stop_the_run(monkeypatch):
    broken, healthy = _alert_inserted_days_ago(1), _alert_inserted_days_ago(1)
    rebuilt = []
    original = Alert.rebuild_index

    def _rebuild_index(self):
        if self.uuid == broken:
            raise RuntimeError("broken")

        rebuilt.append(self.uuid)
        return original(self)

    monkeypatch.setattr(Alert, "rebuild_index", _rebuild_index)

    assert _run(rebuild_index, batch_size=1) == 1
    assert rebuilt == [healthy]


@pytest.mark.integration
def test_rebuild_of_a_missing_directory_fails(monkeypatch):
    root_uuid = _alert_inserted_days_ago(1)
    rebuilt = _record_rebuilds(monkeypatch)

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
    original = Alert.rebuild_index

    def _rebuild_index(self):
        if self.uuid == third:
            raise KeyboardInterrupt()

        rebuilt.append(self.uuid)
        return original(self)

    monkeypatch.setattr(Alert, "rebuild_index", _rebuild_index)

    result = run_alert_sweep(iter_node_alert_id_batches(batch_size=1), _rebuild_alert_index, total=3, after_id=0)

    assert not result.completed
    assert rebuilt == [first, second]
    # everything at or below the resume point is done; the interrupted alert is not
    assert result.resume_after_id == _alert_id(second)

    monkeypatch.setattr(Alert, "rebuild_index", original)
    resumed = _record_rebuilds(monkeypatch)
    assert _run(rebuild_index, after_id=result.resume_after_id) == 0
    assert resumed == [third]


def _ace(*argv) -> int:
    """Runs one `ace alert` command through the real parser; returns its exit code (0 when it returns)."""
    args = get_cli_parser().parse_args(["alert", *argv])
    try:
        args.func(args)
    except SystemExit as e:
        return e.code

    return 0


@pytest.mark.integration
def test_create_writes_a_blank_root(tmp_path):
    storage_dir = str(tmp_path / "manual")

    assert _ace("create", storage_dir) == 0

    root = load_root(storage_dir)
    assert root.description == "Manual Alert"
    assert root.alert_type == "debug"
    assert root.details == {"description": "manually created root"}


def _exported_root(tmp_path, name="export") -> RootAnalysis:
    root = create_root_analysis(uuid=str(uuid.uuid4()), storage_dir=str(tmp_path / name))
    root.initialize_storage()
    root.add_observable_by_spec(F_TEST, "imported")
    root.save()
    return root


@pytest.mark.integration
def test_import_copies_the_alert_into_the_system_and_schedules_it(tmp_path):
    exported = _exported_root(tmp_path)

    assert _ace("import", exported.storage_dir) == 0

    get_db().expire_all()
    alert = get_alert_by_uuid(exported.uuid)
    assert alert.storage_dir == storage_dir_from_uuid(exported.uuid)
    assert alert.location == get_global_runtime_settings().saq_node
    assert alert.company_id == get_config().global_settings.company_id
    assert load_root(alert.storage_dir).get_observable_by_spec(F_TEST, "imported")
    workload = get_db().query(Workload).filter(Workload.uuid == exported.uuid).one()
    assert workload.analysis_mode == ANALYSIS_MODE_CORRELATION


@pytest.mark.integration
def test_import_skips_what_it_cannot_import(tmp_path, caplog):
    """A directory without data.json, and an alert that is already in the system, are each
    logged and skipped; the directories after them are still imported."""
    already_imported = _exported_root(tmp_path, "first")
    assert _ace("import", already_imported.storage_dir) == 0
    exported = _exported_root(tmp_path, "second")
    empty = tmp_path / "empty"
    empty.mkdir()

    assert _ace("import", str(empty), already_imported.storage_dir, exported.storage_dir) == 0

    assert f"{empty}/data.json does not exist" in caplog.text
    assert f"not importing {already_imported.storage_dir}: {storage_dir_from_uuid(already_imported.uuid)} already exists" in caplog.text
    get_db().expire_all()
    assert get_alert_by_uuid(exported.uuid) is not None


@pytest.mark.integration
@pytest.mark.parametrize("absolute", [False, True])
def test_archive_records_the_alert_as_archived(root_analysis, absolute):
    root_analysis.add_observable_by_spec(F_TEST, "test")
    root_analysis.save()
    alert = ALERT(root_analysis)
    storage_dir = get_storage_dir(root_analysis.uuid)

    assert _ace("archive", os.path.abspath(storage_dir) if absolute else storage_dir) == 0

    get_db().expire_all()
    assert get_db().query(Alert.archived).filter(Alert.id == alert.id).scalar() is True


@pytest.mark.integration
def test_archive_skips_a_directory_that_is_not_an_alert(root_analysis, tmp_path, caplog):
    root_analysis.save()
    missing = str(tmp_path / "missing")

    assert _ace("archive", missing, root_analysis.storage_dir) == 0

    assert f"storage directory {missing} does not exist" in caplog.text
    assert f"cannot find alert with storage_dir {root_analysis.storage_dir}" in caplog.text


def _lock_count(root_uuid: str) -> int:
    get_db().expire_all()
    return get_db().query(Lock).filter(Lock.uuid == root_uuid).count()


@pytest.mark.integration
def test_add_observable(root_analysis):
    root_analysis.save()

    assert _ace("add-observable", root_analysis.storage_dir, F_TEST, "added", "-t", "2026-01-02 03:04:05 +0000") == 0

    observable = load_root(root_analysis.storage_dir).find_observable(lambda o: o.type == F_TEST)
    assert observable.value == "added"
    assert observable.time == datetime(2026, 1, 2, 3, 4, 5, tzinfo=pytz.utc)
    assert _lock_count(root_analysis.uuid) == 0


@pytest.mark.integration
def test_add_file_observable_copies_the_file_into_the_alert(root_analysis, tmp_path):
    root_analysis.save()
    path = tmp_path / "sample.txt"
    path.write_text("sample contents")

    assert _ace("add-observable", root_analysis.storage_dir, F_FILE, str(path)) == 0

    observable = load_root(root_analysis.storage_dir).find_observable(lambda o: o.type == F_FILE)
    assert observable.file_name == "sample.txt"
    with open(observable.full_path) as fp:
        assert fp.read() == "sample contents"


@pytest.mark.integration
def test_add_observable_rejects_an_unknown_type(root_analysis, caplog):
    root_analysis.save()

    assert _ace("add-observable", root_analysis.storage_dir, "not_a_type", "value") == 1

    assert "invalid observable type not_a_type" in caplog.text


@pytest.mark.integration
def test_add_observable_rejects_an_invalid_value(root_analysis, caplog):
    root_analysis.save()

    assert _ace("add-observable", root_analysis.storage_dir, F_IPV4, "not an ip") == 1

    assert f"unable to add {F_IPV4} observable not an ip" in caplog.text
    assert load_root(root_analysis.storage_dir).find_observable(lambda o: o.type == F_IPV4) is None
    assert _lock_count(root_analysis.uuid) == 0


@pytest.mark.integration
def test_add_observable_refuses_a_locked_alert(root_analysis, caplog):
    root_analysis.save()
    assert acquire_lock(root_analysis.uuid, str(uuid.uuid4()))

    assert _ace("add-observable", root_analysis.storage_dir, F_TEST, "added") == 1

    assert "unable to lock alert" in caplog.text
    assert load_root(root_analysis.storage_dir).find_observable(lambda o: o.type == F_TEST) is None


@pytest.mark.integration
def test_add_observable_to_a_directory_that_is_not_a_root(tmp_path, caplog):
    assert _ace("add-observable", str(tmp_path), F_TEST, "added") == 1

    assert f"unable to load alert from {tmp_path}" in caplog.text


@pytest.mark.integration
def test_display(root_analysis, capsys):
    root_analysis.add_observable_by_spec(F_TEST, "displayed").add_tag("display_tag")
    root_analysis.save()

    assert _ace("display", root_analysis.storage_dir) == 0

    output = capsys.readouterr().out
    assert "displayed" in output
    assert "* display_tag" in output


@pytest.mark.integration
def test_display_of_a_directory_that_is_not_a_root(tmp_path, caplog):
    assert _ace("display", str(tmp_path)) == 1

    assert f"unable to load alert from {tmp_path}" in caplog.text


@pytest.mark.integration
def test_delete_continues_past_failures(root_analysis, monkeypatch, caplog):
    """A database or filesystem failure on one alert is logged, and the command still exits 0."""
    root_analysis.save()
    ALERT(root_analysis)

    def _fail(*args, **kwargs):
        raise RuntimeError("search is down")

    def _fail_rmtree(path, *args, **kwargs):
        raise OSError("disk is gone")

    monkeypatch.setattr("saq.cli.commands.alerts.submit_delete_task", _fail)
    monkeypatch.setattr("saq.cli.commands.alerts.shutil.rmtree", _fail_rmtree)

    assert _ace("delete", root_analysis.uuid) == 0

    assert f"unable to delete alert {root_analysis.uuid}: search is down" in caplog.text
    assert "unable to delete storage directory" in caplog.text
    assert "disk is gone" in caplog.text


@pytest.mark.unit
def test_cleanup_passes_its_options(monkeypatch):
    calls = []
    monkeypatch.setattr("saq.util.maintenance.cleanup_alerts", lambda **kwargs: calls.append(kwargs))

    assert _ace("cleanup", "--dry-run", "--fp-days-old", "3", "--ignore-days-old", "4", "--simulated-days-old", "5") == 0

    assert calls == [dict(fp_days_old=3, ignore_days_old=4, simulated_days_old=5, dry_run=True)]


@pytest.mark.unit
@pytest.mark.parametrize("argv, expected", [
    ([], lambda settings: (settings.distribute_days_old, False, settings.distribution_target, 0)),
    (["--days", "7", "--dry-run", "--target", "other-node", "--max", "2"], lambda settings: (7, True, "other-node", 2)),
])
def test_distribute_defaults_to_the_configured_target(monkeypatch, argv, expected):
    calls = []
    monkeypatch.setattr("saq.util.maintenance.distribute_old_alerts", lambda *args: calls.append(args))

    assert _ace("distribute", *argv) == 0

    assert calls == [expected(get_config().global_settings)]
