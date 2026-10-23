"""Tests for `ace crash sync` and the replication-aware `ace crash prune`.

The store is a real LocalStorage on a tmp dir, so these exercise genuine uploads and deletes.
"""

import logging
import os
import shutil
from argparse import Namespace

import pytest

from saq.cli.commands.crash import _iter_report_dirs, cli_index, cli_list, cli_prune, cli_sync
from saq.configuration.config import get_config
from saq.crash_replication import list_replicated_ids, remote_report_exists
from saq.crash_report import (
    CRASH_TYPE_EXCEPTION,
    find_crash_report_dir,
    get_crash_report_root_dir,
    get_index_pending_dir,
    record_module_crash,
    remove_from_index_spool,
)
from saq.database.model import AnalysisModuleCrash
from saq.database.pool import get_db


@pytest.fixture
def shared_storage(tmp_path, monkeypatch):
    from saq.storage.adapter import StorageAdapter
    from saq.storage.local import LocalStorage

    adapter = StorageAdapter(LocalStorage(base_dir=str(tmp_path / "shared")))
    monkeypatch.setattr("saq.storage.factory.STORAGE_SYSTEM", adapter)
    monkeypatch.setattr(get_config().crash_reporting, "replicate", True)
    return adapter


def _make_crash(root_analysis) -> str:
    root_analysis.save()
    try:
        raise ValueError("boom")
    except ValueError as e:
        return record_module_crash(
            crash_type=CRASH_TYPE_EXCEPTION,
            module_path="saq.modules.test:BasicTestAnalysis",
            root=root_analysis, exception=e, index=False, replicate=False,
        )


@pytest.mark.unit
def test_sync_is_a_noop_when_replication_is_disabled(root_analysis, capsys):
    _make_crash(root_analysis)
    assert cli_sync(Namespace(dry_run=False)) == 0
    assert "disabled" in capsys.readouterr().out


@pytest.mark.unit
def test_sync_uploads_an_unreplicated_report(root_analysis, shared_storage):
    """The catch-up path: reports the background upload missed, including every timeout-path
    report, which skips replication deliberately."""
    crash_id = _make_crash(root_analysis)
    assert crash_id not in list_replicated_ids()

    assert cli_sync(Namespace(dry_run=False)) == 0
    assert crash_id in list_replicated_ids()


@pytest.mark.unit
def test_sync_dry_run_uploads_nothing(root_analysis, shared_storage):
    crash_id = _make_crash(root_analysis)
    assert cli_sync(Namespace(dry_run=True)) == 0
    assert crash_id not in list_replicated_ids()


@pytest.mark.unit
def test_sync_skips_reports_already_replicated(root_analysis, shared_storage, monkeypatch):
    crash_id = _make_crash(root_analysis)
    cli_sync(Namespace(dry_run=False))
    assert crash_id in list_replicated_ids()

    # a second pass must not re-upload THIS report. the assertion is scoped to it on purpose:
    # cli_sync sweeps every local crash report, and other tests in the same worker leave their own
    # behind in the shared data dir, so "nothing was uploaded at all" is not a property this test
    # can claim.
    uploads = []
    original = shared_storage.upload_file
    monkeypatch.setattr(
        shared_storage, "upload_file",
        lambda *a, **k: (uploads.append(a[2]), original(*a, **k))[1],
    )
    cli_sync(Namespace(dry_run=False))
    assert not [key for key in uploads if key.startswith(f"{crash_id}/")]


@pytest.mark.unit
def test_prune_deletes_the_shared_copy_too(root_analysis, shared_storage):
    crash_id = _make_crash(root_analysis)
    cli_sync(Namespace(dry_run=False))
    assert remote_report_exists(crash_id) is True

    crash_dir = find_crash_report_dir(crash_id)
    # age the report past the retention window
    old = 1000000000
    os.utime(crash_dir, (old, old))

    assert cli_prune(Namespace(days=1, dry_run=False)) == 0
    assert find_crash_report_dir(crash_id) is None
    assert remote_report_exists(crash_id) is False


@pytest.mark.unit
def test_prune_keeps_the_local_copy_if_the_remote_delete_fails(
    root_analysis, shared_storage, monkeypatch
):
    """Remote-first, in lockstep.

    Deleting locally while the shared copy survives would leave a report that every node can still
    serve and that no future prune can ever find -- retention silently unenforced, on malware. A
    failed remote delete must therefore leave the local copy alone so tomorrow's run retries.
    """
    crash_id = _make_crash(root_analysis)
    cli_sync(Namespace(dry_run=False))

    crash_dir = find_crash_report_dir(crash_id)
    old = 1000000000
    os.utime(crash_dir, (old, old))

    def explode(*args, **kwargs):
        raise RuntimeError("object store is unavailable")

    monkeypatch.setattr(shared_storage, "delete_object", explode)

    assert cli_prune(Namespace(days=1, dry_run=False)) == 0
    # still here, and still replicated, so a later run can finish the job
    assert find_crash_report_dir(crash_id) is not None
    assert remote_report_exists(crash_id) is True


#
# ace crash index
#

@pytest.fixture
def empty_spool():
    shutil.rmtree(get_index_pending_dir(), ignore_errors=True)
    yield get_index_pending_dir()
    shutil.rmtree(get_index_pending_dir(), ignore_errors=True)


def _row_count(crash_id: str) -> int:
    get_db().expire_all()
    return get_db().query(AnalysisModuleCrash).filter(AnalysisModuleCrash.uuid == crash_id).count()


def _spooled(spool_dir: str) -> set:
    return set(os.listdir(spool_dir)) if os.path.isdir(spool_dir) else set()


@pytest.mark.integration
def test_index_drains_the_spool(root_analysis, empty_spool, capsys):
    crash_id = _make_crash(root_analysis)
    assert crash_id in _spooled(empty_spool)

    assert cli_index(Namespace(all=False, dry_run=False)) == 0

    assert _row_count(crash_id) == 1
    assert crash_id not in _spooled(empty_spool)
    assert "indexed 1 spooled" in capsys.readouterr().out


@pytest.mark.integration
def test_index_dry_run_indexes_nothing(root_analysis, empty_spool, capsys):
    crash_id = _make_crash(root_analysis)

    cli_index(Namespace(all=False, dry_run=True))
    cli_index(Namespace(all=True, dry_run=True))

    assert _row_count(crash_id) == 0
    assert crash_id in _spooled(empty_spool)
    assert f"would index {crash_id}" in capsys.readouterr().out


@pytest.mark.integration
def test_index_all_backfills_reports_with_no_spool_entry(root_analysis, empty_spool):
    """Reports written before the spool existed have no entry; --all finds them anyway."""
    crash_id = _make_crash(root_analysis)
    remove_from_index_spool(crash_id)

    cli_index(Namespace(all=False, dry_run=False))
    assert _row_count(crash_id) == 0

    cli_index(Namespace(all=True, dry_run=False))
    assert _row_count(crash_id) == 1

    # and a second pass does not duplicate it
    cli_index(Namespace(all=True, dry_run=False))
    assert _row_count(crash_id) == 1


@pytest.mark.integration
def test_prune_drops_spool_entries(root_analysis, empty_spool):
    crash_id = _make_crash(root_analysis)
    assert crash_id in _spooled(empty_spool)

    # age the report past the retention window
    old = 1000000000
    os.utime(find_crash_report_dir(crash_id), (old, old))
    cli_prune(Namespace(days=1, dry_run=False))

    assert find_crash_report_dir(crash_id) is None
    assert crash_id not in _spooled(empty_spool)


@pytest.mark.unit
def test_report_iteration_never_walks_the_spool(root_analysis, empty_spool):
    crash_id = _make_crash(root_analysis)
    assert crash_id in _spooled(empty_spool)

    walked = [path for path, _ in _iter_report_dirs(get_crash_report_root_dir())]
    assert walked
    assert not any(path.startswith(empty_spool) for path in walked)


#
# a crash report directory of its own, for the tests that look at everything under it
#

@pytest.fixture
def private_root(tmp_path, monkeypatch):
    root_dir = tmp_path / "crash_reports"
    # an absolute directory replaces the data dir in get_crash_report_root_dir()
    monkeypatch.setattr(get_config().crash_reporting, "directory", str(root_dir))
    return root_dir


def _age(crash_id: str):
    old = 1000000000
    os.utime(find_crash_report_dir(crash_id), (old, old))


@pytest.mark.unit
def test_list_without_a_root_dir(private_root, capsys):
    assert cli_list(Namespace(limit=50)) == 0
    assert "does not exist" in capsys.readouterr().out


@pytest.mark.unit
def test_list_with_no_reports(private_root, capsys):
    (private_root / "index_pending").mkdir(parents=True)

    assert cli_list(Namespace(limit=50)) == 0
    assert capsys.readouterr().out == "no crash reports\n"


@pytest.mark.unit
def test_list_shows_newest_first_and_incomplete_reports(private_root, root_analysis, capsys):
    first = _make_crash(root_analysis)
    second = _make_crash(root_analysis)
    # a report killed mid write has no metadata.json; it is listed rather than hidden
    incomplete_dir = private_root / "2020" / "01" / "01" / "not-a-crash-id"
    incomplete_dir.mkdir(parents=True)

    assert cli_list(Namespace(limit=50)) == 0
    lines = capsys.readouterr().out.splitlines()

    assert lines[0].split() == ["CRASH", "ID", "TYPE", "TIMESTAMP", "MODULE"]
    crash_ids = [line.split()[0] for line in lines[1:]]
    assert crash_ids == [second, first, "not-a-crash-id"]
    assert lines[1].split()[1] == CRASH_TYPE_EXCEPTION
    assert lines[1].split()[-1] == "saq.modules.test:BasicTestAnalysis"
    assert lines[3].split()[1] == "?"


@pytest.mark.unit
def test_list_honors_the_limit(private_root, root_analysis, capsys):
    _make_crash(root_analysis)
    newest = _make_crash(root_analysis)

    cli_list(Namespace(limit=1))
    lines = capsys.readouterr().out.splitlines()
    assert [line.split()[0] for line in lines[1:]] == [newest]


@pytest.mark.unit
def test_report_iteration_skips_stray_files(private_root, root_analysis):
    crash_id = _make_crash(root_analysis)
    crash_dir = find_crash_report_dir(crash_id)
    day_dir = os.path.dirname(crash_dir)
    month_dir = os.path.dirname(day_dir)
    year_dir = os.path.dirname(month_dir)
    for path in (os.path.join(str(private_root), "1999"), os.path.join(year_dir, "13"),
                 os.path.join(month_dir, "32"), os.path.join(day_dir, "stray")):
        with open(path, "w") as fp:
            fp.write("not a directory")

    assert [path for path, _ in _iter_report_dirs(str(private_root))] == [crash_dir]


@pytest.mark.unit
def test_prune_reports_stale_hang_stack_dumps(private_root, monkeypatch, capsys):
    monkeypatch.setattr("saq.crash_report.prune_stale_hang_stacks", lambda: 2)

    assert cli_prune(Namespace(days=1, dry_run=False)) == 0
    assert "pruned 2 stale hang stack dump(s)" in capsys.readouterr().out


@pytest.mark.unit
def test_prune_with_retention_disabled_removes_nothing(private_root, root_analysis, monkeypatch, capsys):
    crash_id = _make_crash(root_analysis)
    _age(crash_id)
    monkeypatch.setattr(get_config().crash_reporting, "retention_days", 0)

    assert cli_prune(Namespace(days=None, dry_run=False)) == 0
    assert "retention is disabled" in capsys.readouterr().out
    assert find_crash_report_dir(crash_id) is not None


@pytest.mark.unit
def test_prune_without_a_root_dir(private_root, capsys):
    assert cli_prune(Namespace(days=1, dry_run=True)) == 0
    assert capsys.readouterr().out == ""


@pytest.mark.integration
def test_prune_dry_run_removes_nothing(private_root, root_analysis, empty_spool, capsys):
    old_id = _make_crash(root_analysis)
    _age(old_id)
    recent_id = _make_crash(root_analysis)

    assert cli_prune(Namespace(days=1, dry_run=True)) == 0

    out = capsys.readouterr().out
    assert f"would remove {find_crash_report_dir(old_id)}" in out
    assert recent_id not in out
    assert "would prune 1 crash report(s) older than 1 days" in out
    assert find_crash_report_dir(old_id) is not None
    assert old_id in _spooled(empty_spool)


@pytest.mark.integration
def test_prune_removes_only_old_reports_and_their_date_dirs(private_root, root_analysis, empty_spool, capsys):
    old_id = _make_crash(root_analysis)
    cli_index(Namespace(all=True, dry_run=False))
    old_dir = find_crash_report_dir(old_id)
    # move it to a date of its own so its date levels empty out
    aged_dir = private_root / "2001" / "09" / "09" / old_id
    aged_dir.parent.mkdir(parents=True)
    shutil.move(old_dir, aged_dir)
    _age(old_id)
    recent_id = _make_crash(root_analysis)
    assert _row_count(old_id) == 1

    assert cli_prune(Namespace(days=1, dry_run=False)) == 0

    assert "pruned 1 crash report(s) older than 1 days" in capsys.readouterr().out
    assert find_crash_report_dir(old_id) is None
    assert not (private_root / "2001").exists()
    assert _row_count(old_id) == 0
    assert find_crash_report_dir(recent_id) is not None


@pytest.mark.unit
def test_prune_logs_a_directory_it_cannot_remove(private_root, root_analysis, monkeypatch, caplog):
    crash_id = _make_crash(root_analysis)
    _age(crash_id)
    deleted = []
    monkeypatch.setattr("saq.cli.commands.crash._delete_rows", deleted.extend)

    def refuse(path):
        raise PermissionError("read-only file system")

    monkeypatch.setattr("saq.cli.commands.crash.shutil.rmtree", refuse)

    with caplog.at_level(logging.ERROR):
        assert cli_prune(Namespace(days=1, dry_run=False)) == 0

    [record] = [r for r in caplog.records if "unable to remove crash report" in r.getMessage()]
    assert record.levelno == logging.ERROR
    # with its traceback, so the error report is written and the operator hears about it
    assert record.exc_info is not None
    assert find_crash_report_dir(crash_id) is not None
    # its index row is kept, since the report is still there
    assert deleted == []


@pytest.mark.unit
def test_prune_logs_index_rows_it_cannot_delete(private_root, root_analysis, monkeypatch, caplog):
    crash_id = _make_crash(root_analysis)
    _age(crash_id)

    def no_database():
        raise RuntimeError("database is unavailable")

    monkeypatch.setattr("saq.database.pool.get_db", no_database)

    with caplog.at_level(logging.ERROR):
        assert cli_prune(Namespace(days=1, dry_run=False)) == 0

    [record] = [r for r in caplog.records if "unable to delete crash report index rows" in r.getMessage()]
    assert crash_id in record.getMessage()
    assert record.exc_info is not None
    # the directory is gone regardless: a surviving row is only a listing inaccuracy
    assert find_crash_report_dir(crash_id) is None


@pytest.mark.unit
def test_index_without_a_root_dir(private_root, capsys):
    assert cli_index(Namespace(all=True, dry_run=False)) == 0
    assert capsys.readouterr().out == "indexed 0 crash report(s)\n"


@pytest.mark.unit
def test_index_all_warns_about_a_report_it_cannot_index(private_root, root_analysis, monkeypatch, caplog, capsys):
    crash_id = _make_crash(root_analysis)
    monkeypatch.setattr("saq.cli.commands.crash._indexed_ids", lambda crash_ids: set())
    monkeypatch.setattr("saq.crash_report.index_crash_report", lambda crash_id: None)
    monkeypatch.setattr("saq.crash_report.drain_index_spool", lambda: [])

    assert cli_index(Namespace(all=True, dry_run=False)) == 0

    assert f"unable to index crash report {crash_id}" in caplog.text
    assert "indexed 0 crash report(s); 0 already indexed" in capsys.readouterr().out


@pytest.mark.unit
def test_sync_without_a_root_dir(private_root, shared_storage, capsys):
    assert cli_sync(Namespace(dry_run=False)) == 0
    assert capsys.readouterr().out == ""


@pytest.mark.unit
def test_sync_warns_about_a_report_it_cannot_replicate(private_root, root_analysis, shared_storage, monkeypatch, caplog, capsys):
    crash_id = _make_crash(root_analysis)
    monkeypatch.setattr("saq.crash_replication.replicate_report", lambda crash_dir, crash_id: False)

    assert cli_sync(Namespace(dry_run=False)) == 0

    assert f"unable to replicate crash report {crash_id}" in caplog.text
    assert "replicated 0 crash report(s); 0 already in shared storage" in capsys.readouterr().out
