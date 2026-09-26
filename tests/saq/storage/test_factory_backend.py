"""Unit tests for the pluggable storage backend (storage.target: custom).

The factory loads the backend class from config, validates the YAML `config:` sub-dict against
the class's own get_config_class() model, and passes that model to the constructor. These use a
real backend class defined in this module rather than a mock, so the whole path -- import,
attribute lookup, pydantic validation, construction -- actually runs.
"""

from typing import Optional, Type
from unittest.mock import patch

import pytest
from pydantic import Field, ValidationError

from saq.configuration.schema import StorageBackendSpec, StorageConfig
from saq.storage.adapter import StorageAdapter
from saq.storage.error import StorageError
from saq.storage.factory import StorageFactory
from saq.storage.interface import StorageBackendConfig

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


def _config(target: str = "custom", backend: Optional[StorageBackendSpec] = None):
    """A stand-in for get_config() carrying just the storage block the factory reads."""

    class _Config:
        storage = StorageConfig(target=target, backend=backend)
        s3 = None

    return _Config()


def _spec(python_class: str = "SampleBackend", **config) -> StorageBackendSpec:
    return StorageBackendSpec(
        python_module=__name__, python_class=python_class, config=config
    )


def test_custom_backend_is_loaded_and_wrapped():
    """The class named in config is constructed and handed back inside a StorageAdapter."""
    spec = _spec(required_setting="value")
    with patch("saq.storage.factory.get_config", return_value=_config(backend=spec)):
        adapter = StorageFactory.get_storage_system()

    assert isinstance(adapter, StorageAdapter)
    assert isinstance(adapter._storage, SampleBackend)
    assert adapter._storage.config.required_setting == "value"
    assert adapter._storage.config.optional_setting is None


def test_backend_config_is_validated_by_its_own_model():
    """The `config:` sub-dict goes through the backend's get_config_class(), not the base."""
    spec = _spec(required_setting="a", optional_setting="b")
    with patch("saq.storage.factory.get_config", return_value=_config(backend=spec)):
        adapter = StorageFactory.get_storage_system()

    assert isinstance(adapter._storage.config, SampleBackendConfig)
    assert adapter._storage.config.optional_setting == "b"


def test_invalid_backend_config_is_a_storage_error():
    """A config the backend's model rejects fails at construction, not at first upload."""
    spec = _spec()  # required_setting missing
    with patch("saq.storage.factory.get_config", return_value=_config(backend=spec)):
        with pytest.raises(StorageError):
            StorageFactory.get_storage_system()


def test_custom_target_without_backend_is_an_error():
    with patch("saq.storage.factory.get_config", return_value=_config(backend=None)):
        with pytest.raises(StorageError, match="storage.backend is not configured"):
            StorageFactory.get_storage_system()


def test_backend_with_non_custom_target_is_an_error():
    """Silently ignoring the spec would leave every node writing to its own disk while the
    deployment believes replication is on."""
    spec = _spec(required_setting="value")
    with patch("saq.storage.factory.get_config", return_value=_config(target="local", backend=spec)):
        with pytest.raises(StorageError, match="set storage.target to custom"):
            StorageFactory.get_storage_system()


def test_unimportable_module_names_the_module():
    spec = StorageBackendSpec(
        python_module="no.such.module", python_class="Whatever", config={}
    )
    with patch("saq.storage.factory.get_config", return_value=_config(backend=spec)):
        with pytest.raises(StorageError, match="no.such.module"):
            StorageFactory.get_storage_system()


def test_missing_class_names_the_class():
    spec = _spec(python_class="NoSuchBackend")
    with patch("saq.storage.factory.get_config", return_value=_config(backend=spec)):
        with pytest.raises(StorageError, match="NoSuchBackend"):
            StorageFactory.get_storage_system()


def test_backend_without_get_config_class_is_rejected():
    spec = _spec(python_class="BackendWithoutConfigClass")
    with patch("saq.storage.factory.get_config", return_value=_config(backend=spec)):
        with pytest.raises(StorageError, match="get_config_class"):
            StorageFactory.get_storage_system()
