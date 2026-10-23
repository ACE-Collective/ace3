import logging
import os
import os.path
import sys

from saq.configuration import (
        YAMLConfig,
        ConfigurationException)
from saq.configuration.loader import load_configuration
from saq.configuration.schema import ACEConfig, APIConfig

import pytest
from pydantic import ValidationError

@pytest.mark.unit
def test_apply_config(tmp_path):
    yaml_path_1 = str(tmp_path / '1.yaml')
    yaml_path_2 = str(tmp_path / '2.yaml')

    with open(yaml_path_1, 'w') as fp:
        fp.write("""
global:
  test_1: 1
  test_2: 2
""")

    with open(yaml_path_2, 'w') as fp:
        fp.write("""
global:
  test_1: 4
  test_3: 3
""")

    config = YAMLConfig()
    config.load_file(yaml_path_1)
    config.load_file(yaml_path_2)

    # test that changes made in override are in config
    assert config._data['global']['test_1'] == 4
    # test that settings in config that were not changed are the same
    assert config._data['global']['test_2'] == 2
    # test that new settings in override are added
    assert config._data['global']['test_3'] == 3

@pytest.mark.unit
def test_load_configuration_file(tmp_path):
    # make sure we can load a configuration file
    yaml_path = str(tmp_path / 'test.yaml')
    with open(yaml_path, 'w') as fp:
        fp.write("""
global:
  test: true
""")

    config = YAMLConfig()
    config.load_file(yaml_path)
    assert config._data['global']['test'] is True

@pytest.mark.unit
def test_load_configuration_file_override(tmp_path):
    # make sure we can override an existing configuration file
    yaml_path = str(tmp_path / 'test.yaml')
    with open(yaml_path, 'w') as fp:
        fp.write("""
global:
  test: true
""")

    yaml_path_override = str(tmp_path / 'test_override.yaml')
    with open(yaml_path_override, 'w') as fp:
        fp.write("""
global:
  test: false
  new_option: value
""")

    config = YAMLConfig()
    config.load_file(yaml_path)
    config.load_file(yaml_path_override)
    assert config._data['global']['test'] is False
    assert config._data['global']['new_option'] == 'value'

@pytest.mark.unit
def test_load_configuration_reference(tmp_path):
    # tests recursively loading configuration files
    yaml_path_1 = str(tmp_path / '1.yaml')
    yaml_path_2 = str(tmp_path / '2.yaml')
    yaml_path_3 = str(tmp_path / '3.yaml')

    # 1.yaml references 2.yaml
    with open(yaml_path_1, 'w') as fp:
        fp.write(f"""
config:
  config_2: {yaml_path_2}
""")

    # 2.yaml references 3.yaml
    with open(yaml_path_2, 'w') as fp:
        fp.write(f"""
config:
  config_3: {yaml_path_3}
""")

    with open(yaml_path_3, 'w') as fp:
        fp.write("""
global:
  loaded_3: true
""")

    config = YAMLConfig()
    config.load_file(yaml_path_1)
    assert config._data['global']['loaded_3'] is True

@pytest.mark.unit
def test_load_configuration_missing_reference(tmp_path, caplog):
    yaml_path_1 = str(tmp_path / '1.yaml')
    yaml_path_2 = str(tmp_path / '2.yaml')

    assert not os.path.exists(yaml_path_2)

    # 1.yaml references 2.yaml which does not exist
    with open(yaml_path_1, 'w') as fp:
        fp.write(f"""
config:
  config_2: {yaml_path_2}
""")

    config = YAMLConfig()

    config.load_file(yaml_path_1)
    assert "skipping non-existent YAML include path in YAML config" in caplog.text

@pytest.mark.unit
def test_load_configuration_no_references(tmp_path):
    yaml_path_1 = str(tmp_path / '1.yaml')
    with open(yaml_path_1, 'w') as fp:
        fp.write("""
global:
  option: test
""")

    config = YAMLConfig()
    config.load_file(yaml_path_1)

@pytest.mark.unit
def test_load_path_references(tmp_path):
    temp_dir = tmp_path / 'temp_dir'
    temp_dir.mkdir()
    temp_dir = str(temp_dir)

    yaml_path_1 = str(tmp_path / '1.yaml')
    with open(yaml_path_1, 'w') as fp:
        fp.write(f"""
path:
  site_config_dir: {temp_dir}
""")

    config = YAMLConfig()
    config.load_file(yaml_path_1)
    config.apply_path_references()
    assert temp_dir in sys.path
@pytest.mark.unit
def test_unittest_config_paths_overlay_wins(tmp_path, monkeypatch):
    # SAQ_UNITTEST_CONFIG_PATHS is merged *after* etc/saq.unittest.default.yaml, which is what
    # lets the test suite point the database settings at the databases it provisions per
    # session. SAQ_CONFIG_PATHS is merged before it and so cannot do that.
    early_path = str(tmp_path / 'early.yaml')
    with open(early_path, 'w') as fp:
        fp.write("""
database_ace:
  database: from-saq-config-paths
""")

    late_path = str(tmp_path / 'late.yaml')
    with open(late_path, 'w') as fp:
        fp.write("""
database_ace:
  database: from-unittest-config-paths
""")

    monkeypatch.setenv("SAQ_CONFIG_PATHS", early_path)
    monkeypatch.setenv("SAQ_UNITTEST_CONFIG_PATHS", late_path)
    config = load_configuration(config_paths=[])
    assert config._data['database_ace']['database'] == 'from-unittest-config-paths'
    # the unittest default is still merged over SAQ_CONFIG_PATHS
    monkeypatch.delenv("SAQ_UNITTEST_CONFIG_PATHS")
    config = load_configuration(config_paths=[])
    assert config._data['database_ace']['database'] == 'ace-unittest'

@pytest.mark.unit
def test_unittest_config_paths_missing_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SAQ_UNITTEST_CONFIG_PATHS", str(tmp_path / 'missing.yaml'))
    config = load_configuration(config_paths=[])
    assert config._data['database_ace']['database'] == 'ace-unittest'
    assert 'SAQ_UNITTEST_CONFIG_PATHS' in capsys.readouterr().err


@pytest.mark.unit
def test_api_config_ignores_secret_key():
    # a site overlay may still set api.secret_key, which nothing reads; it must not fail validation
    config = APIConfig.model_validate({
        "listen_address": "0.0.0.0",
        "listen_port": 443,
        "ssl_cert": "ssl/ace.cert.pem",
        "ssl_key": "ssl/ace.key.pem",
        "default_alert_type": "default",
        "api_key": "key",
        "prefix": "AUTO",
        "secret_key": "left-over",
    })
    assert not hasattr(config, "secret_key")


def _load_with_overlay(tmp_path, overlay: str) -> ACEConfig:
    overlay_path = str(tmp_path / 'overlay.yaml')
    with open(overlay_path, 'w') as fp:
        fp.write(overlay)

    raw_config = load_configuration(config_paths=[overlay_path])
    config = ACEConfig.model_validate(raw_config._data)
    config.raw = raw_config
    return config

@pytest.mark.unit
@pytest.mark.parametrize("overlay", [
    "analysis_module_removed_module:\n  enabled: false\n",
    "analysis_module_removed_module:\n  group_execs: ceo,2,executive\n",
])
def test_overlay_of_removed_analysis_module_is_ignored(tmp_path, caplog, overlay):
    # the module's block in saq.default.yaml is gone, so the overlay's keys are all that is left of it
    caplog.set_level(logging.WARNING)
    config = _load_with_overlay(tmp_path, overlay)

    with pytest.raises(ValueError):
        config.get_analysis_module_config("removed_module")
    records = [r for r in caplog.records if getattr(r, "config_key", None) == "analysis_module_removed_module"]
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING

@pytest.mark.unit
def test_incomplete_analysis_module_definition_still_fails(tmp_path):
    # a block that names a module but leaves out its class is a mistake, not a leftover
    with pytest.raises(ValidationError):
        _load_with_overlay(tmp_path, """
analysis_module_half_written:
  name: half_written
  python_module: saq.modules.test
  enabled: true
""")
