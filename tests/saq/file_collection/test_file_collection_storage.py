import logging
import os
import shutil
import time
from types import SimpleNamespace

import pytest

from saq.cli.commands import file_collection as file_collection_cli
from saq.environment import get_base_dir, get_global_runtime_settings
from saq.file_collection import storage
from saq.file_collection.storage import prune_unattached_files, unattached_storage_dir

DAY = 86400


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(get_global_runtime_settings(), "data_dir", str(tmp_path))
    monkeypatch.setattr(get_global_runtime_settings(), "saq_node", "node1")
    return tmp_path


def _collection_dir(data_dir, node: str, collection_id: int, age_days: float):
    path = data_dir / "file_collection" / node / str(collection_id)
    path.mkdir(parents=True)
    (path / "history.zip").write_bytes(b"zip")
    mtime = time.time() - age_days * DAY
    os.utime(path, (mtime, mtime))
    return path


@pytest.mark.unit
def test_unattached_storage_dir(data_dir):
    path = unattached_storage_dir(42)
    assert not os.path.isabs(path)
    assert os.path.normpath(os.path.join(get_base_dir(), path)) == str(data_dir / "file_collection" / "node1" / "42")


@pytest.mark.unit
def test_prune_removes_only_expired(data_dir):
    old = _collection_dir(data_dir, "node1", 1, age_days=8)
    fresh = _collection_dir(data_dir, "node1", 2, age_days=1)

    assert prune_unattached_files(7) == 1
    assert not old.exists()
    assert fresh.exists()


@pytest.mark.unit
def test_prune_removes_a_stray_file(data_dir):
    stray = data_dir / "file_collection" / "node1" / "stray.zip"
    stray.parent.mkdir(parents=True)
    stray.write_bytes(b"zip")
    mtime = time.time() - 8 * DAY
    os.utime(stray, (mtime, mtime))

    assert prune_unattached_files(7) == 1
    assert not stray.exists()


@pytest.mark.unit
def test_prune_leaves_other_nodes_alone(data_dir):
    other = _collection_dir(data_dir, "node2", 1, age_days=30)

    assert prune_unattached_files(7) == 0
    assert other.exists()


@pytest.mark.unit
def test_prune_without_directory(data_dir):
    assert prune_unattached_files(7) == 0


@pytest.mark.unit
def test_prune_dry_run(data_dir):
    old = _collection_dir(data_dir, "node1", 1, age_days=8)

    assert prune_unattached_files(7, dry_run=True) == 1
    assert old.exists()


@pytest.mark.unit
def test_prune_continues_past_a_failure(data_dir, monkeypatch, caplog):
    stuck = _collection_dir(data_dir, "node1", 1, age_days=8)
    old = _collection_dir(data_dir, "node1", 2, age_days=8)
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


@pytest.mark.unit
def test_cli_prune(data_dir, monkeypatch, capsys):
    _collection_dir(data_dir, "node1", 1, age_days=8)
    monkeypatch.setattr(file_collection_cli, "get_service_config", lambda name: SimpleNamespace(retention_days=7))

    assert file_collection_cli.cli_prune(SimpleNamespace(dry_run=False)) == 0
    assert "removed 1 collection(s) older than 7 days" in capsys.readouterr().out


@pytest.mark.unit
def test_cli_prune_without_service(data_dir, monkeypatch, capsys):
    old = _collection_dir(data_dir, "node1", 1, age_days=8)

    def not_configured(name):
        raise ValueError(f"service config for {name} not found")

    monkeypatch.setattr(file_collection_cli, "get_service_config", not_configured)

    assert file_collection_cli.cli_prune(SimpleNamespace(dry_run=False)) == 0
    assert "not configured" in capsys.readouterr().out
    assert old.exists()
