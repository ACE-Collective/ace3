"""Tests for `ace hunt verify`, `ace hunt list` and `ace hunt list-types`."""

import shutil
from argparse import Namespace

import pytest
import yaml

from saq.cli.commands.hunt import list_hunt_types, list_hunts, verify_hunt
from saq.configuration.config import get_config
from saq.configuration.schema import HuntTypeConfig


@pytest.fixture
def test_hunt_type(tmp_path):
    rules_dir = tmp_path / "rules"
    shutil.copytree("tests/data/hunts/test/generic", rules_dir)
    with open(rules_dir / "test_3.yaml", "w") as fp:
        yaml.dump({
            "rule": {
                "uuid": "0f0b6a3e-2f4c-4d3c-9a51-7e1f3c6d2b10",
                "enabled": False,
                "name": "unit_test_3",
                "description": "Unit Test Description 3",
                "type": "test",
                "alert_type": "test - alert",
                "frequency": "00:00:10",
                "instance_types": ["unittest"],
            }
        }, fp)

    get_config().clear_hunt_type_configs()
    get_config().add_hunt_type_config("test", HuntTypeConfig(
        name="test",
        python_module="tests.saq.collectors.hunter.test_base_hunter",
        python_class="TestHunt",
        rule_dirs=[{"rule_dir": str(rules_dir)}],
        update_frequency=60,
    ))
    yield
    get_config().load_hunt_type_configs()


@pytest.mark.integration
def test_list_hunts(test_hunt_type, capsys):
    with pytest.raises(SystemExit) as exc_info:
        list_hunts(Namespace())

    assert exc_info.value.code == 0
    # enabled hunts first, then by name
    assert capsys.readouterr().out.splitlines() == [
        "E test:test_1 - unit_test_1",
        "E test:test_2 - unit_test_2",
        "D test:test_3 - unit_test_3",
    ]


@pytest.mark.integration
def test_list_hunt_types(test_hunt_type, capsys):
    with pytest.raises(SystemExit) as exc_info:
        list_hunt_types(Namespace())

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.splitlines() == ["test"]


@pytest.mark.integration
def test_verify_hunts(test_hunt_type, capsys):
    with pytest.raises(SystemExit) as exc_info:
        verify_hunt(Namespace())

    assert exc_info.value.code == 0
    assert "hunt syntax verified" in capsys.readouterr().out


@pytest.mark.integration
def test_verify_hunts_fails_on_invalid_hunt(test_hunt_type, tmp_path, capsys):
    with open(tmp_path / "rules" / "broken.yaml", "w") as fp:
        fp.write("rule:\n  name: broken\n")

    with pytest.raises(SystemExit) as exc_info:
        verify_hunt(Namespace())

    assert exc_info.value.code == 1
    assert "unable to load 1 test hunts" in capsys.readouterr().err
