import logging
import os
import shutil
import time
from types import SimpleNamespace

import pytest
from sqlalchemy import func, text, update

from saq.cli.commands import file_collection as file_collection_cli
from saq.constants import F_FILE_LOCATION
from saq.database.model import FileCollection
from saq.database.pool import get_db
from saq.environment import get_base_dir, get_global_runtime_settings
from saq.file_collection import storage
from saq.file_collection.database import delete_file_collection, queue_file_collection
from saq.file_collection.storage import prune_unattached_files, unattached_storage_dir
from saq.file_collection.types import FileCollectionStatus, FileCollectorStatus

DAY = 86400


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(get_global_runtime_settings(), "data_dir", str(tmp_path))
    monkeypatch.setattr(get_global_runtime_settings(), "saq_node", "node1")
    return tmp_path


def _set_mtime(path, age_days: float):
    mtime = time.time() - age_days * DAY
    os.utime(path, (mtime, mtime))


def _collection_dir(data_dir, completed_days_ago=None, node: str = "node1", mtime_days_ago: float = 0):
    """Queues an alert-less collection and creates its directory. With completed_days_ago the
    collection completed (its last attempt) that many days ago by the database clock; without it the
    collection is still pending."""
    collection_id = queue_file_collection(
        collector_name="custom",
        observable_type=F_FILE_LOCATION,
        observable_value="host@/path/to/file",
    )
    if completed_days_ago is not None:
        get_db().execute(update(FileCollection).where(FileCollection.id == collection_id).values(
            status=FileCollectionStatus.COMPLETED.value,
            result=FileCollectorStatus.SUCCESS.value,
            update_time=func.date_sub(func.now(), text(f"INTERVAL {int(completed_days_ago)} DAY")),
        ))
        get_db().commit()

    path = data_dir / "file_collection" / node / str(collection_id)
    path.mkdir(parents=True)
    (path / "history.zip").write_bytes(b"zip")
    _set_mtime(path, mtime_days_ago)
    return path


@pytest.mark.unit
def test_unattached_storage_dir(data_dir):
    path = unattached_storage_dir(42)
    assert not os.path.isabs(path)
    assert os.path.normpath(os.path.join(get_base_dir(), path)) == str(data_dir / "file_collection" / "node1" / "42")


@pytest.mark.integration
def test_prune_removes_only_expired(data_dir):
    old = _collection_dir(data_dir, completed_days_ago=8)
    fresh = _collection_dir(data_dir, completed_days_ago=1)

    assert prune_unattached_files(7) == 1
    assert not old.exists()
    assert fresh.exists()


@pytest.mark.integration
def test_prune_ages_by_last_attempt_not_directory_mtime(data_dir):
    """A collection retried into its old directory leaves the directory's mtime alone; the row's
    update_time is what says when it was last collected."""
    retried = _collection_dir(data_dir, completed_days_ago=1, mtime_days_ago=30)

    assert prune_unattached_files(7) == 0
    assert retried.exists()


@pytest.mark.integration
def test_prune_keeps_pending_collections(data_dir):
    pending = _collection_dir(data_dir, mtime_days_ago=30)

    assert prune_unattached_files(7) == 0
    assert pending.exists()


@pytest.mark.integration
def test_prune_removes_files_of_a_deleted_collection(data_dir):
    orphan = _collection_dir(data_dir, completed_days_ago=1)
    delete_file_collection(int(orphan.name))

    assert prune_unattached_files(7) == 1
    assert not orphan.exists()


@pytest.mark.integration
def test_prune_removes_a_stray_file(data_dir):
    stray = data_dir / "file_collection" / "node1" / "stray.zip"
    stray.parent.mkdir(parents=True)
    stray.write_bytes(b"zip")

    assert prune_unattached_files(7) == 1
    assert not stray.exists()


@pytest.mark.integration
def test_prune_leaves_other_nodes_alone(data_dir):
    other = _collection_dir(data_dir, completed_days_ago=30, node="node2")

    assert prune_unattached_files(7) == 0
    assert other.exists()


@pytest.mark.integration
def test_prune_without_directory(data_dir):
    assert prune_unattached_files(7) == 0


@pytest.mark.integration
def test_prune_dry_run(data_dir):
    old = _collection_dir(data_dir, completed_days_ago=8)

    assert prune_unattached_files(7, dry_run=True) == 1
    assert old.exists()


@pytest.mark.integration
def test_prune_looks_up_collections_in_batches(data_dir, monkeypatch):
    monkeypatch.setattr(storage, "PRUNE_BATCH_SIZE", 2)
    old = [_collection_dir(data_dir, completed_days_ago=8) for _ in range(3)]
    fresh = [_collection_dir(data_dir, completed_days_ago=1) for _ in range(2)]

    assert prune_unattached_files(7) == 3
    assert not any(path.exists() for path in old)
    assert all(path.exists() for path in fresh)


@pytest.mark.integration
def test_prune_continues_past_a_failure(data_dir, monkeypatch, caplog):
    stuck = _collection_dir(data_dir, completed_days_ago=8)
    old = _collection_dir(data_dir, completed_days_ago=8)
    real_rmtree = shutil.rmtree

    def rmtree(path, *args, **kwargs):
        if path == str(stuck):
            raise PermissionError("denied")
        real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(storage.shutil, "rmtree", rmtree)
    with caplog.at_level(logging.ERROR):
        assert prune_unattached_files(7) == 1

    assert stuck.exists()
    assert not old.exists()
    assert any(r.levelno == logging.ERROR and r.exc_info and "unable to remove" in r.getMessage() for r in caplog.records)


@pytest.mark.integration
def test_cli_prune(data_dir, monkeypatch, capsys):
    _collection_dir(data_dir, completed_days_ago=8)
    monkeypatch.setattr(file_collection_cli, "get_service_config", lambda name: SimpleNamespace(retention_days=7))

    assert file_collection_cli.cli_prune(SimpleNamespace(dry_run=False)) == 0
    assert "removed 1 collection(s) older than 7 days" in capsys.readouterr().out


@pytest.mark.integration
def test_cli_prune_without_service(data_dir, monkeypatch, capsys):
    old = _collection_dir(data_dir, completed_days_ago=8)

    def not_configured(name):
        raise ValueError(f"service config for {name} not found")

    monkeypatch.setattr(file_collection_cli, "get_service_config", not_configured)

    assert file_collection_cli.cli_prune(SimpleNamespace(dry_run=False)) == 0
    assert "not configured" in capsys.readouterr().out
    assert old.exists()
