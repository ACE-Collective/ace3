"""Unit tests for the storage factory and its pluggable backend (storage.target: custom).

The factory loads the backend class from config, validates the YAML `config:` sub-dict against
the class's own get_config_class() model, and passes that model to the constructor. These use a
real backend class defined in this module rather than a mock, so the whole path -- import,
attribute lookup, pydantic validation, construction -- actually runs.
"""

from typing import Optional, Type

import pytest
from pydantic import Field, ValidationError

from saq.configuration.config import get_config
from saq.configuration.schema import StorageBackendSpec, StorageConfig
from saq.storage.adapter import StorageAdapter
from saq.storage.error import StorageError
from saq.storage.factory import StorageFactory
from saq.storage.interface import StorageBackendConfig
from saq.storage.local import LocalStorage

pytestmark = pytest.mark.unit


class SampleBackendConfig(StorageBackendConfig):
    required_setting: str = Field(...)
    optional_setting: Optional[str] = Field(default=None)


class SampleBackend:
    """A backend that records what it was constructed with. Deliberately does not subclass
    StorageInterface -- the Protocol is structural, and the factory must not require it."""

    @classmethod
    def get_config_class(cls) -> Type[StorageBackendConfig]:
        return SampleBackendConfig

    def __init__(self, config: SampleBackendConfig):
        self.config = config


class BackendWithoutConfigClass:
    def __init__(self, config):
        self.config = config


# BackendWithoutConfigClass is only ever looked up by name, so silence the unused warning
_ = BackendWithoutConfigClass


def _configure(monkeypatch, target: str = "custom", backend: Optional[StorageBackendSpec] = None):
    monkeypatch.setattr(get_config(), "storage", StorageConfig(target=target, backend=backend))


def _spec(python_class: str = "SampleBackend", **config) -> StorageBackendSpec:
    return StorageBackendSpec(
        python_module=__name__, python_class=python_class, config=config
    )


def test_custom_backend_is_loaded_and_wrapped(monkeypatch):
    """The class named in config is constructed and handed back inside a StorageAdapter."""
    spec = _spec(required_setting="value")
    _configure(monkeypatch, backend=spec)
    adapter = StorageFactory.get_storage_system()

    assert isinstance(adapter, StorageAdapter)
    assert isinstance(adapter._storage, SampleBackend)
    assert adapter._storage.config.required_setting == "value"
    assert adapter._storage.config.optional_setting is None


def test_backend_config_is_validated_by_its_own_model(monkeypatch):
    """The `config:` sub-dict goes through the backend's get_config_class(), not the base."""
    spec = _spec(required_setting="a", optional_setting="b")
    _configure(monkeypatch, backend=spec)
    adapter = StorageFactory.get_storage_system()

    assert isinstance(adapter._storage.config, SampleBackendConfig)
    assert adapter._storage.config.optional_setting == "b"


def test_invalid_backend_config_is_a_storage_error(monkeypatch):
    """A config the backend's model rejects fails at construction, not at first upload."""
    spec = _spec()  # required_setting missing
    _configure(monkeypatch, backend=spec)
    with pytest.raises(StorageError):
        StorageFactory.get_storage_system()


def test_custom_target_without_backend_is_an_error(monkeypatch):
    _configure(monkeypatch, backend=None)
    with pytest.raises(StorageError, match="storage.backend is not configured"):
        StorageFactory.get_storage_system()


def test_backend_with_non_custom_target_is_an_error(monkeypatch):
    """Silently ignoring the spec would leave every node writing to its own disk while the
    deployment believes replication is on."""
    spec = _spec(required_setting="value")
    _configure(monkeypatch, target="local", backend=spec)
    with pytest.raises(StorageError, match="set storage.target to custom"):
        StorageFactory.get_storage_system()


def test_unimportable_module_names_the_module(monkeypatch):
    spec = StorageBackendSpec(
        python_module="no.such.module", python_class="Whatever", config={}
    )
    _configure(monkeypatch, backend=spec)
    with pytest.raises(StorageError, match="no.such.module"):
        StorageFactory.get_storage_system()


def test_missing_class_names_the_class(monkeypatch):
    spec = _spec(python_class="NoSuchBackend")
    _configure(monkeypatch, backend=spec)
    with pytest.raises(StorageError, match="NoSuchBackend"):
        StorageFactory.get_storage_system()


def test_backend_without_get_config_class_is_rejected(monkeypatch):
    spec = _spec(python_class="BackendWithoutConfigClass")
    _configure(monkeypatch, backend=spec)
    with pytest.raises(StorageError, match="get_config_class"):
        StorageFactory.get_storage_system()


def test_local_target_builds_local_storage_under_base_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(get_config(), "storage", StorageConfig(target="local", base_dir=str(tmp_path)))
    adapter = StorageFactory.get_storage_system()

    assert isinstance(adapter._storage, LocalStorage)
    source = tmp_path / "source"
    source.write_bytes(b"x")
    adapter.upload_file(source, "bucket", "key")
    assert (tmp_path / "bucket" / "key").read_bytes() == b"x"


def test_s3_target_is_rejected_by_name():
    """The built-in s3 backend is gone. A deployment still configured for it must fail at config
    validation, saying what to do, rather than quietly fall back to every node's own disk."""
    with pytest.raises(ValidationError, match="storage.target s3 is no longer supported"):
        StorageConfig(target="s3")


def test_unknown_target_is_rejected():
    with pytest.raises(ValidationError):
        StorageConfig(target="nfs")
