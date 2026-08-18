"""tests for resolving signature locations out of the runtime configuration

these mutate the loaded configuration objects directly. tests/conftest.py deep
copies and restores the configuration around every test, so that is safe."""

import logging
import os
import subprocess

import pytest

from saq.configuration.config import get_config, get_service_config
from saq.constants import ANALYSIS_MODULE_OBSERVABLE_MODIFIER, SERVICE_YARA_SCANNER
from saq.configuration.schema import HuntRuleDirConfig, HuntTypeConfig
from saq.environment import get_base_dir
from saq.signatures.locations import get_all_signature_locations, get_signature_locations
from saq.signatures.model import SignatureType


def _init_repo(path: str):
    """init a git repo at path with one commit"""
    os.makedirs(path, exist_ok=True)
    subprocess.run(["git", "init", path], check=True, capture_output=True)
    with open(os.path.join(path, "README"), "w") as fp:
        fp.write("signatures\n")
    subprocess.run(["git", "-C", path, "add", "."], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", path, "-c", "user.name=unittest", "-c", "user.email=unittest@localhost",
         "commit", "-m", "init"],
        check=True, capture_output=True)


def _set_yara_config(monkeypatch, signature_dir: str, git_repo_dirs: list[str]):
    config = get_service_config(SERVICE_YARA_SCANNER)
    monkeypatch.setattr(config, "signature_dir", signature_dir)
    monkeypatch.setattr(config, "git_repo_dirs", git_repo_dirs)


def _set_hunt_types(*hunt_types: HuntTypeConfig):
    get_config().clear_hunt_type_configs()
    for hunt_type in hunt_types:
        get_config().add_hunt_type_config(hunt_type.name, hunt_type)


def _hunt_type(name: str, rule_dirs: list[HuntRuleDirConfig], schedulable: bool = True) -> HuntTypeConfig:
    return HuntTypeConfig(
        name=name,
        python_module="saq.collectors.query_hunter",
        python_class="QueryHunt",
        rule_dirs=rule_dirs,
        update_frequency=60,
        schedulable=schedulable,
    )


def _observable_modifier_config():
    return get_config().get_analysis_module_config(ANALYSIS_MODULE_OBSERVABLE_MODIFIER)


#
# yara
#

@pytest.mark.unit
def test_yara_location(tmp_path, monkeypatch):
    """The location is the signature_dir itself, not one per rule subdirectory -
    the loader mirrors the scanner's traversal of it."""
    signature_dir = str(tmp_path / "yara")
    os.makedirs(os.path.join(signature_dir, "bv"))
    _set_yara_config(monkeypatch, signature_dir, [])

    locations = get_signature_locations(SignatureType.YARA)

    assert len(locations) == 1
    assert locations[0].signature_type == SignatureType.YARA
    assert locations[0].path == signature_dir
    assert locations[0].git_dirs == ()
    assert locations[0].source == "service_yara"
    assert locations[0].exists()


@pytest.mark.unit
def test_yara_signature_dir_is_resolved_against_saq_home(monkeypatch):
    _set_yara_config(monkeypatch, "signatures/yara", [])

    assert get_signature_locations(SignatureType.YARA)[0].path == os.path.join(
        get_base_dir(), "signatures", "yara")


@pytest.mark.unit
@pytest.mark.parametrize("entry_form", ["name", "relative", "absolute"])
def test_yara_git_repo_dirs_are_resolved(tmp_path, monkeypatch, entry_form):
    """An entry may be a subdirectory name, a relative path or an absolute one -
    the same forms YaraScanner._resolve_signature_subdir accepts - and comes back
    as an absolute path."""
    signature_dir = str(tmp_path / "yara")
    rule_dir = os.path.join(signature_dir, "bv")
    _init_repo(rule_dir)

    entry = {"name": "bv", "relative": "./bv", "absolute": rule_dir}[entry_form]
    _set_yara_config(monkeypatch, signature_dir, [entry])

    location = get_signature_locations(SignatureType.YARA)[0]
    assert len(location.git_dirs) == 1
    assert os.path.isabs(location.git_dirs[0])
    assert os.path.realpath(location.git_dirs[0]) == os.path.realpath(rule_dir)


@pytest.mark.unit
def test_yara_git_repo_dirs_entry_that_is_not_a_repo_is_dropped(tmp_path, monkeypatch, caplog):
    """get_validated_git_repo_dirs drops it so the rules are still scanned, and
    the location has to report the same thing the scanner is given."""
    signature_dir = str(tmp_path / "yara")
    os.makedirs(os.path.join(signature_dir, "bv"))
    _set_yara_config(monkeypatch, signature_dir, ["bv", "missing"])

    with caplog.at_level(logging.ERROR):
        location = get_signature_locations(SignatureType.YARA)[0]

    assert location.git_dirs == ()
    assert len(caplog.records) == 2


@pytest.mark.unit
def test_yara_location_that_does_not_exist(tmp_path, monkeypatch):
    """A node without the rule repo checked out still resolves a location - the
    missing directory is what `ace signatures locations` exists to show."""
    _set_yara_config(monkeypatch, str(tmp_path / "missing"), [])

    assert not get_signature_locations(SignatureType.YARA)[0].exists()


#
# hunts
#

@pytest.mark.unit
def test_hunt_locations(tmp_path):
    splunk_dir = str(tmp_path / "hunts" / "splunk")
    logscale_dir = str(tmp_path / "hunts" / "logscale")
    repo = str(tmp_path)

    _set_hunt_types(
        _hunt_type("splunk", [HuntRuleDirConfig(rule_dir=splunk_dir, git_dir=repo)]),
        _hunt_type("logscale", [HuntRuleDirConfig(rule_dir=logscale_dir)]),
    )

    locations = get_signature_locations(SignatureType.HUNT)

    assert len(locations) == 2
    assert all(location.signature_type == SignatureType.HUNT for location in locations)

    by_source = {location.source: location for location in locations}
    assert by_source["hunt_type_splunk"].path == splunk_dir
    assert by_source["hunt_type_splunk"].git_dirs == (repo,)

    # no git_dir configured means the hunts here are unversioned, which is what
    # HuntManager records for them
    assert by_source["hunt_type_logscale"].path == logscale_dir
    assert by_source["hunt_type_logscale"].git_dirs == ()


@pytest.mark.unit
def test_hunt_rule_dirs_are_resolved_against_saq_home():
    _set_hunt_types(_hunt_type("splunk", [
        HuntRuleDirConfig(rule_dir="signatures/hunts/splunk", git_dir="signatures")]))

    location = get_signature_locations(SignatureType.HUNT)[0]
    assert location.path == os.path.join(get_base_dir(), "signatures", "hunts", "splunk")
    assert location.git_dirs == (os.path.join(get_base_dir(), "signatures"),)


@pytest.mark.unit
def test_hunt_type_with_several_rule_dirs(tmp_path):
    _set_hunt_types(_hunt_type("splunk", [
        HuntRuleDirConfig(rule_dir=str(tmp_path / "a")),
        HuntRuleDirConfig(rule_dir=str(tmp_path / "b")),
    ]))

    locations = get_signature_locations(SignatureType.HUNT)
    assert [location.path for location in locations] == [str(tmp_path / "a"), str(tmp_path / "b")]


@pytest.mark.unit
def test_non_schedulable_hunt_type_has_no_locations():
    """Its rule_dirs are never scanned, so no hunt of that type is ever loaded."""
    _set_hunt_types(_hunt_type("validation_only", [], schedulable=False))

    assert get_signature_locations(SignatureType.HUNT) == []


@pytest.mark.unit
def test_no_hunt_types_configured():
    _set_hunt_types()

    assert get_signature_locations(SignatureType.HUNT) == []


#
# observable modifier
#

@pytest.mark.unit
def test_observable_modifier_location(tmp_path, monkeypatch):
    rules_file = str(tmp_path / "rules" / "observable_modifier_rules.yaml")
    config = _observable_modifier_config()
    monkeypatch.setattr(config, "rules_config_path", rules_file)
    monkeypatch.setattr(config, "git_dir", str(tmp_path))

    locations = get_signature_locations(SignatureType.OBSERVABLE_MODIFIER)

    assert len(locations) == 1
    assert locations[0].signature_type == SignatureType.OBSERVABLE_MODIFIER
    assert locations[0].path == rules_file
    assert locations[0].git_dirs == (str(tmp_path),)
    assert locations[0].source == "analysis_module_observable_modifier"


@pytest.mark.unit
def test_observable_modifier_paths_are_resolved_against_saq_home(monkeypatch):
    config = _observable_modifier_config()
    monkeypatch.setattr(config, "rules_config_path", "etc/observable_modifier_rules.yaml")
    monkeypatch.setattr(config, "git_dir", None)

    location = get_signature_locations(SignatureType.OBSERVABLE_MODIFIER)[0]
    assert location.path == os.path.join(get_base_dir(), "etc", "observable_modifier_rules.yaml")
    assert location.git_dirs == ()


@pytest.mark.unit
def test_disabled_observable_modifier_has_no_locations(monkeypatch, caplog):
    monkeypatch.setattr(_observable_modifier_config(), "enabled", False)

    with caplog.at_level(logging.WARNING):
        assert get_signature_locations(SignatureType.OBSERVABLE_MODIFIER) == []

    assert any("disabled" in record.getMessage() for record in caplog.records)


#
# built-ins and the union
#

@pytest.mark.unit
def test_builtin_signatures_have_no_location():
    assert get_signature_locations(SignatureType.BUILTIN) == []


@pytest.mark.unit
def test_get_all_signature_locations(tmp_path, monkeypatch):
    _set_yara_config(monkeypatch, str(tmp_path / "yara"), [])
    _set_hunt_types(_hunt_type("splunk", [HuntRuleDirConfig(rule_dir=str(tmp_path / "hunts"))]))
    monkeypatch.setattr(_observable_modifier_config(), "rules_config_path", str(tmp_path / "rules.yaml"))

    locations = get_all_signature_locations()

    assert [location.signature_type for location in locations] == [
        SignatureType.YARA, SignatureType.HUNT, SignatureType.OBSERVABLE_MODIFIER]
