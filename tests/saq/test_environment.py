import os
import tempfile

import pytest

from saq.configuration.loader import load_configuration
from saq.configuration.schema import StorageConfig
from saq.configuration.config import get_config
from saq.environment import get_base_dir, get_global_runtime_settings, initialize_base_dir, resolve_temp_dir
from saq.storage.factory import StorageFactory

pytestmark = pytest.mark.unit


def _make_home(path):
    os.makedirs(path / "saq")
    return str(path)


def test_initialize_base_dir_argument_wins_over_env(tmp_path, monkeypatch):
    home = _make_home(tmp_path / "arg")
    monkeypatch.setenv("SAQ_HOME", _make_home(tmp_path / "env"))
    initialize_base_dir(home)
    assert get_base_dir() == home


def test_initialize_base_dir_uses_env(tmp_path, monkeypatch):
    home = _make_home(tmp_path / "env")
    monkeypatch.setenv("SAQ_HOME", home)
    initialize_base_dir()
    assert get_base_dir() == home


def test_initialize_base_dir_keeps_default_without_env(tmp_path, monkeypatch):
    home = _make_home(tmp_path / "default")
    monkeypatch.delenv("SAQ_HOME", raising=False)
    get_global_runtime_settings().saq_home = home
    initialize_base_dir()
    assert get_base_dir() == home


def test_initialize_base_dir_makes_relative_absolute(tmp_path, monkeypatch):
    _make_home(tmp_path / "home")
    monkeypatch.chdir(tmp_path)
    initialize_base_dir("home")
    assert get_base_dir() == str(tmp_path / "home")


def test_initialize_base_dir_missing_dir(tmp_path):
    with pytest.raises(RuntimeError, match="does not exist"):
        initialize_base_dir(str(tmp_path / "missing"))


def test_initialize_base_dir_not_ace(tmp_path):
    with pytest.raises(RuntimeError, match="no saq directory"):
        initialize_base_dir(str(tmp_path))


def test_load_configuration_does_not_depend_on_cwd(tmp_path, monkeypatch):
    # etc/saq.default.yaml used to be opened relative to the cwd
    monkeypatch.chdir(tmp_path)
    config = load_configuration(config_paths=[])
    assert os.path.join(get_base_dir(), "etc", "saq.default.yaml") in config.loaded_files


def test_resolve_temp_dir_relative_is_under_saq_home(tmp_path):
    get_global_runtime_settings().saq_home = str(tmp_path)
    assert resolve_temp_dir("var/tmp") == str(tmp_path / "var" / "tmp")


def test_resolve_temp_dir_absolute(tmp_path):
    assert resolve_temp_dir(str(tmp_path / "tmp")) == str(tmp_path / "tmp")


def test_resolve_temp_dir_unset():
    assert resolve_temp_dir(None) == os.path.join(tempfile.gettempdir(), "ace")


def test_local_storage_relative_base_dir_is_under_saq_home(tmp_path, monkeypatch):
    # resolved through get_base_dir(), not $SAQ_HOME
    monkeypatch.delenv("SAQ_HOME", raising=False)
    get_global_runtime_settings().saq_home = str(tmp_path)
    monkeypatch.setattr(get_config(), "storage", StorageConfig(target="local", base_dir="storage"))
    monkeypatch.setattr(get_config(), "s3", None)
    adapter = StorageFactory.get_storage_system()
    assert str(adapter._storage.base_dir) == str(tmp_path / "storage")
