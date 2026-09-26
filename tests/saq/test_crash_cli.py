"""Tests for `ace crash sync` and the replication-aware `ace crash prune`.

The store is a real LocalStorage on a tmp dir, so these exercise genuine uploads and deletes.
"""

import os
import shutil
from argparse import Namespace

import pytest

from saq.cli.commands.crash import _iter_report_dirs, cli_index, cli_prune, cli_sync
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
