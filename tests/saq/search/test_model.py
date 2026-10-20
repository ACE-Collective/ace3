"""download_model() fetches the embedding model once per data volume, under a lock, atomically;
load_model() never downloads (docs/SEARCH.md, "The embedding model")."""

import fcntl
import json
import logging
import os
import sys
import threading
import types

import pytest

from saq.configuration.config import get_config
from saq.search import model as search_model
from saq.search.model import (
    MODEL_COMPLETE_FILE,
    clear_model_cache,
    download_model,
    get_model_cache_path,
    is_model_downloaded,
    load_model,
    model_slug,
)
from tests.saq.helpers import wait_for_condition

pytestmark = pytest.mark.unit

MODEL_NAME = "all-MiniLM-L6-v2"


class FakeSentenceTransformer:
    """Records how it was constructed; save() writes the files a real model writes, modules.json last."""

    instances: list["FakeSentenceTransformer"] = []
    fail_save = False

    def __init__(self, name_or_path, device=None, cache_folder=None):
        self.name_or_path = name_or_path
        self.cache_folder = cache_folder
        FakeSentenceTransformer.instances.append(self)
        if cache_folder is not None:
            # what the hub download leaves behind
            os.makedirs(cache_folder, exist_ok=True)
            with open(os.path.join(cache_folder, "blob"), "w") as fp:
                fp.write("weights")

    def save(self, path):
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, "model.safetensors"), "w") as fp:
            fp.write("weights")
        if FakeSentenceTransformer.fail_save:
            raise OSError("disk full")
        with open(os.path.join(path, MODEL_COMPLETE_FILE), "w") as fp:
            json.dump([], fp)


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(get_config().search, "model_cache_dir", str(tmp_path / "models"))
    monkeypatch.setattr(get_config().search, "embedding_model", MODEL_NAME)
    clear_model_cache()
    yield tmp_path / "models"
    clear_model_cache()


@pytest.fixture(autouse=True)
def fake_sentence_transformers(monkeypatch):
    FakeSentenceTransformer.instances = []
    FakeSentenceTransformer.fail_save = False
    module = types.ModuleType("sentence_transformers")
    module.SentenceTransformer = FakeSentenceTransformer
    monkeypatch.setitem(sys.modules, "sentence_transformers", module)
    return FakeSentenceTransformer


def _write_complete_model(path):
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, MODEL_COMPLETE_FILE), "w") as fp:
        json.dump([], fp)


def test_download_saves_one_complete_copy(cache_dir, caplog):
    with caplog.at_level(logging.INFO):
        path = download_model()

    assert path == get_model_cache_path()
    assert is_model_downloaded()
    [created] = FakeSentenceTransformer.instances
    assert created.name_or_path == MODEL_NAME
    # the hub cache was kept out of ~/.cache and removed with the staging directory
    assert created.cache_folder.startswith(str(cache_dir))
    assert not os.path.exists(created.cache_folder)
    assert sorted(entry for entry in os.listdir(cache_dir) if not entry.endswith(".lock")) == [model_slug()]

    downloaded = [record for record in caplog.records if record.getMessage() == "search_model_downloaded"]
    assert len(downloaded) == 1
    assert downloaded[0].model == MODEL_NAME
    assert downloaded[0].path == path


def test_download_skips_a_model_already_there(cache_dir):
    _write_complete_model(get_model_cache_path())
    assert download_model() == get_model_cache_path()
    assert FakeSentenceTransformer.instances == []


def test_download_replaces_an_incomplete_directory(cache_dir, caplog):
    path = get_model_cache_path()
    os.makedirs(path)
    with open(os.path.join(path, "model.safetensors"), "w") as fp:
        fp.write("half")

    assert not is_model_downloaded()
    with caplog.at_level(logging.INFO):
        download_model()

    assert is_model_downloaded()
    assert len(FakeSentenceTransformer.instances) == 1
    assert any(record.getMessage() == "search_model_replacing_incomplete" for record in caplog.records)


def test_download_removes_staging_left_by_a_killed_download(cache_dir):
    stale = cache_dir / f".{model_slug()}-download-killed"
    os.makedirs(stale / "model")
    download_model()
    assert not stale.exists()


def test_failed_save_leaves_nothing_that_looks_downloaded(cache_dir):
    FakeSentenceTransformer.fail_save = True
    with pytest.raises(OSError, match="disk full"):
        download_model()

    assert not is_model_downloaded()
    assert not os.path.exists(get_model_cache_path())
    assert [entry for entry in os.listdir(cache_dir) if not entry.endswith(".lock")] == []


def _hold_lock(cache_dir):
    os.makedirs(cache_dir, exist_ok=True)
    lock_file = open(os.path.join(cache_dir, f".{model_slug()}.lock"), "a")
    fcntl.flock(lock_file, fcntl.LOCK_EX)
    return lock_file


def test_waiter_uses_the_model_another_process_downloaded(cache_dir, caplog):
    lock_file = _hold_lock(cache_dir)
    result = {}

    def download():
        result["path"] = download_model(timeout=30)

    with caplog.at_level(logging.INFO):
        thread = threading.Thread(target=download)
        thread.start()
        try:
            assert wait_for_condition(lambda: any(record.getMessage() == "search_model_download_waiting" for record in caplog.records))
            # the lock holder finishes its download and lets go
            _write_complete_model(get_model_cache_path())
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)
            lock_file.close()
        thread.join(timeout=30)

    assert not thread.is_alive()
    assert result["path"] == get_model_cache_path()
    assert FakeSentenceTransformer.instances == []


def test_lock_wait_times_out(cache_dir, monkeypatch):
    lock_file = _hold_lock(cache_dir)
    monkeypatch.setattr(search_model.time, "sleep", lambda seconds: None)
    try:
        with pytest.raises(TimeoutError, match="waiting for another process"):
            download_model(timeout=0)
    finally:
        lock_file.close()

    assert FakeSentenceTransformer.instances == []


def test_lock_wait_retries_until_the_holder_lets_go(cache_dir, monkeypatch):
    lock_file = _hold_lock(cache_dir)
    sleeps = []

    def sleep(seconds):
        # the first retry still finds the lock held; the holder finishes before the second
        sleeps.append(seconds)
        if len(sleeps) == 2:
            fcntl.flock(lock_file, fcntl.LOCK_UN)

    monkeypatch.setattr(search_model.time, "sleep", sleep)
    try:
        path = download_model(timeout=30)
    finally:
        lock_file.close()

    assert len(sleeps) == 2
    assert path == get_model_cache_path()
    assert is_model_downloaded()
    assert len(FakeSentenceTransformer.instances) == 1


def test_lock_wait_stops_on_shutdown(cache_dir):
    lock_file = _hold_lock(cache_dir)
    try:
        with pytest.raises(RuntimeError, match="shutting down"):
            download_model(stopping=lambda: True)
    finally:
        lock_file.close()


def test_load_never_downloads(cache_dir):
    with pytest.raises(FileNotFoundError, match="ace search download-model"):
        load_model()
    assert FakeSentenceTransformer.instances == []


def test_load_reads_the_downloaded_copy_once(cache_dir):
    _write_complete_model(get_model_cache_path())
    first = load_model()
    assert load_model() is first
    [created] = FakeSentenceTransformer.instances
    assert created.name_or_path == get_model_cache_path()
    assert created.cache_folder is None
