"""Tests for `ace crash sync` and the replication-aware `ace crash prune`.

The store is a real LocalStorage on a tmp dir, so these exercise genuine uploads and deletes.
"""

import os
from argparse import Namespace

import pytest

from saq.cli.commands.crash import cli_prune, cli_sync
from saq.configuration.config import get_config
from saq.crash_replication import list_replicated_ids, remote_report_exists
from saq.crash_report import (
    CRASH_TYPE_EXCEPTION,
    find_crash_report_dir,
    record_module_crash,
)


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
