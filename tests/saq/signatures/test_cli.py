"""tests for the ace signatures CLI

the handlers are called directly with a Namespace rather than through the ace
script, which has heavy import time side effects. importing saq.signatures.cli
registers its parser on the shared subparser, which happens once per session."""

import argparse
import json
import os

import pytest

from saq.configuration.config import get_config, get_service_config
from saq.constants import ANALYSIS_MODULE_OBSERVABLE_MODIFIER, SERVICE_YARA_SCANNER
from saq.signatures.builtin import BUILTIN_SIGNATURES, GENERIC
from saq.signatures.cli import cli_list_locations, cli_list_signatures
from saq.signatures.model import SignatureType


def _list_args(types: list[str] | None = None, as_json: bool = False) -> argparse.Namespace:
    return argparse.Namespace(type=types, json=as_json, verbose=False)


@pytest.fixture(autouse=True)
def empty_signature_config(tmp_path, monkeypatch):
    """Points every configured location at nothing, so a test that does not care
    about a type gets no signatures of it rather than whatever this checkout
    happens to have on disk."""
    yara_config = get_service_config(SERVICE_YARA_SCANNER)
    monkeypatch.setattr(yara_config, "signature_dir", str(tmp_path / "yara"))
    monkeypatch.setattr(yara_config, "git_repo_dirs", [])

    get_config().clear_hunt_type_configs()

    monkeypatch.setattr(
        get_config().get_analysis_module_config(ANALYSIS_MODULE_OBSERVABLE_MODIFIER),
        "rules_config_path", str(tmp_path / "rules.yaml"))


@pytest.mark.unit
def test_list_builtin_signatures(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli_list_signatures(_list_args(["builtin"]))

    assert excinfo.value.code == 0

    captured = capsys.readouterr()
    assert GENERIC.name in captured.out
    # one header row, one separator row, one row per signature
    assert len(captured.out.strip().splitlines()) == len(BUILTIN_SIGNATURES) + 2
    assert f"{len(BUILTIN_SIGNATURES)} signatures" in captured.err


@pytest.mark.unit
def test_list_signatures_as_json(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli_list_signatures(_list_args(["builtin"], as_json=True))

    assert excinfo.value.code == 0

    signatures = json.loads(capsys.readouterr().out)
    assert len(signatures) == len(BUILTIN_SIGNATURES)
    assert {s["uuid"] for s in signatures} == set(BUILTIN_SIGNATURES)

    # the full record, not the abbreviated table
    assert set(signatures[0]) == {
        "name", "uuid", "type", "version", "git_remote", "source_path", "content_hash", "tags"}
    assert isinstance(signatures[0]["tags"], list)


@pytest.mark.unit
def test_list_signatures_type_filter(capsys):
    with pytest.raises(SystemExit):
        cli_list_signatures(_list_args(["yara"], as_json=True))

    assert json.loads(capsys.readouterr().out) == []


@pytest.mark.unit
def test_list_signatures_reports_an_unreadable_location(capsys):
    """The yara signature_dir does not exist, which is normal on a node without
    the rule repo checked out. It is reported, not raised."""
    with pytest.raises(SystemExit) as excinfo:
        cli_list_signatures(_list_args(["yara", "builtin"]))

    # the failure is reported...
    assert excinfo.value.code == 1
    # ...but the types that did load are still listed
    assert GENERIC.name in capsys.readouterr().out


@pytest.mark.unit
def test_list_locations(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli_list_locations(_list_args(as_json=True))

    # the yara signature_dir does not exist, so this doubles as a config check
    assert excinfo.value.code == 1

    locations = json.loads(capsys.readouterr().out)
    assert [location["signature_type"] for location in locations] == [
        SignatureType.YARA, SignatureType.OBSERVABLE_MODIFIER]
    assert all(os.path.isabs(location["path"]) for location in locations)
    assert not any(location["exists"] for location in locations)


@pytest.mark.unit
def test_list_locations_table(tmp_path, capsys):
    os.makedirs(tmp_path / "yara")
    with open(tmp_path / "rules.yaml", "w") as fp:
        fp.write("rules: []\n")

    with pytest.raises(SystemExit) as excinfo:
        cli_list_locations(_list_args(["yara", "observable_modifier"]))

    assert excinfo.value.code == 0
    assert "service_yara" in capsys.readouterr().out
