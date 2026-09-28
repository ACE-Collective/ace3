import errno
import io
import os
import time

import pytest
from pydantic import BaseModel

from saq.cas.backend import BackendEntry, LocalBackend, digest_from_key, load_backend, object_key
from saq.cas.errors import BackendKeyNotFound, CASConfigError
from saq.configuration.schema import CASBackendSpec, CASConfig, CASPoolConfig

DIGEST = "ab" + "cd" + "0" * 60
KEY = object_key("p", DIGEST)


class _FakeConfig(BaseModel):
    flag: bool = False


class FakeBackend:
    """A custom backend used by the loader tests. Says it is node-local."""
    node_local = True

    def __init__(self, config: _FakeConfig):
        self.config = config

    @classmethod
    def get_config_class(cls):
        return _FakeConfig


class NoNodeLocal:
    def __init__(self, config):
        pass

    @classmethod
    def get_config_class(cls):
        return _FakeConfig


class _Explodes(io.RawIOBase):
    def readable(self):
        return True

    def readinto(self, b):
        raise OSError("boom")


@pytest.mark.unit
def test_keys():
    assert KEY == f"p/ab/cd/{DIGEST}"
    assert digest_from_key(KEY) == DIGEST
    assert digest_from_key("p/ab/cd/short") is None
    assert digest_from_key(f"p/xx/cd/{DIGEST}") is None        # shard does not match
    assert digest_from_key(f"p/ab/{DIGEST}") is None           # wrong depth
    assert digest_from_key(f"p/ab/cd/{DIGEST.upper()}") is None


@pytest.mark.unit
def test_write_open_exists_delete(tmp_path):
    backend = LocalBackend(str(tmp_path))
    assert not backend.exists(KEY)
    backend.write(KEY, io.BytesIO(b"hello"))
    assert backend.exists(KEY)
    with backend.open(KEY) as fp:
        assert fp.read() == b"hello"

    # idempotent: a second write of the same key is a no-op
    backend.write(KEY, io.BytesIO(b"hello"))
    assert (tmp_path / "p" / "ab" / "cd" / DIGEST).read_bytes() == b"hello"

    backend.delete(KEY)
    assert not backend.exists(KEY)
    backend.delete(KEY)     # missing is not an error
    with pytest.raises(BackendKeyNotFound):
        with backend.open(KEY):
            pass

    # the empty shard directories went with it, the root stays
    assert not (tmp_path / "p" / "ab").exists()
    assert tmp_path.exists()


@pytest.mark.unit
def test_failed_write_leaves_nothing(tmp_path):
    backend = LocalBackend(str(tmp_path))
    with pytest.raises(OSError):
        backend.write(KEY, _Explodes())

    assert not backend.exists(KEY)
    assert list(backend.iter_entries()) == []
    assert not any(name.startswith(".tmp-") for _, _, names in os.walk(tmp_path) for name in names)


@pytest.mark.unit
def test_iter_entries_and_temp_sweep(tmp_path):
    backend = LocalBackend(str(tmp_path))
    backend.write(KEY, io.BytesIO(b"hello"))
    other = object_key("q", "ff" * 32)
    backend.write(other, io.BytesIO(b"x" * 10))
    stray = tmp_path / "p" / "ab" / "cd" / ".tmp-leftover"
    stray.write_bytes(b"partial")

    entries = {entry.key: entry for entry in backend.iter_entries()}
    assert set(entries) == {KEY, other}
    assert entries[KEY].size == 5 and entries[other].size == 10
    assert isinstance(entries[KEY], BackendEntry) and entries[KEY].mtime > 0

    assert [entry.key for entry in backend.iter_entries("p/")] == [KEY]
    assert list(backend.iter_entries("nope/")) == []

    # the stray temp file is only swept once it is old enough
    assert backend.sweep_temp_files(time.time() - 3600) == 0
    assert stray.exists()
    assert backend.sweep_temp_files(time.time() + 1) == 1
    assert not stray.exists()


@pytest.mark.unit
def test_link(tmp_path, monkeypatch):
    backend = LocalBackend(str(tmp_path / "store"))
    backend.write(KEY, io.BytesIO(b"hello"))
    dest = tmp_path / "dest"
    assert backend.link(KEY, str(dest))
    assert os.stat(dest).st_ino == os.stat(backend.path(KEY)).st_ino

    with pytest.raises(FileExistsError):
        backend.link(KEY, str(dest))

    def cross_device(*_):
        raise OSError(errno.EXDEV, "cross-device link")

    monkeypatch.setattr(os, "link", cross_device)
    assert backend.link(KEY, str(tmp_path / "dest2")) is False


@pytest.mark.unit
def test_load_local_backend_roots(tmp_path, monkeypatch):
    monkeypatch.setattr("saq.cas.backend.get_data_dir", lambda: str(tmp_path))
    cas_config = CASConfig(local_root="cas")
    backend = load_backend("p", CASPoolConfig(), cas_config)
    assert isinstance(backend, LocalBackend)
    assert backend.root == str(tmp_path / "cas" / "p")

    backend = load_backend("p", CASPoolConfig(root="elsewhere/p"), cas_config)
    assert backend.root == str(tmp_path / "elsewhere" / "p")

    backend = load_backend("p", CASPoolConfig(root=str(tmp_path / "abs")), cas_config)
    assert backend.root == str(tmp_path / "abs")


@pytest.mark.unit
def test_load_custom_backend():
    spec = CASBackendSpec(python_module=__name__, python_class="FakeBackend", config={"flag": True})
    backend = load_backend("p", CASPoolConfig(backend="custom", custom=spec), CASConfig())
    assert isinstance(backend, FakeBackend) and backend.config.flag is True

    with pytest.raises(CASConfigError, match="declared shared but its backend is node-local"):
        load_backend("p", CASPoolConfig(backend="custom", custom=spec, shared=True), CASConfig())

    with pytest.raises(CASConfigError, match="must declare node_local"):
        load_backend("p", CASPoolConfig(backend="custom", custom=CASBackendSpec(
            python_module=__name__, python_class="NoNodeLocal")), CASConfig())

    with pytest.raises(CASConfigError, match="cannot import"):
        load_backend("p", CASPoolConfig(backend="custom", custom=CASBackendSpec(
            python_module="no.such.module", python_class="X")), CASConfig())

    with pytest.raises(CASConfigError, match="has no class"):
        load_backend("p", CASPoolConfig(backend="custom", custom=CASBackendSpec(
            python_module=__name__, python_class="Missing")), CASConfig())

    with pytest.raises(CASConfigError, match="invalid backend config"):
        load_backend("p", CASPoolConfig(backend="custom", custom=CASBackendSpec(
            python_module=__name__, python_class="FakeBackend", config={"flag": "not a bool"})), CASConfig())
