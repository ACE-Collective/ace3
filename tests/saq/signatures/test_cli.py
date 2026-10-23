"""tests for the ace signatures CLI

the handlers are called directly with a Namespace rather than through the ace
script, which has heavy import time side effects. importing
saq.cli.commands.signatures registers its parser on the shared subparser, which
happens once per session."""

import argparse
import json
import logging
import os

import pytest

from saq.configuration.config import get_config, get_service_config
from saq.constants import (
    ANALYSIS_MODULE_OBSERVABLE_MODIFIER,
    ANALYSIS_MODULE_SNORT_SIGNATURE_ANALYSIS_V1,
    SERVICE_YARA_SCANNER,
)
from saq.signatures.builtin import BUILTIN_SIGNATURES, GENERIC
from saq.cli.commands.signatures import (
    _abbreviate_version,
    build_signature_db,
    cli_list_locations,
    cli_list_signatures,
)
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
        "name", "uuid", "type", "version", "git_remote", "source_path", "content_hash", "tags",
        "modifiers", "enabled"}
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


@pytest.mark.unit
def test_abbreviate_version():
    commit = "0123456789abcdef0123456789abcdef01234567"
    assert _abbreviate_version(commit) == "0123456789ab"
    # hex, but not a commit hash
    assert _abbreviate_version("abc123") == "abc123"
    assert _abbreviate_version("3.1.0") == "3.1.0"
    assert _abbreviate_version("unknown") == "unknown"


def _yara_rule(name: str, rule_uuid: str) -> str:
    return f"""\
rule {name}
{{
    meta:
        uuid = "{rule_uuid}"

    strings:
        $a = "{name}"

    condition:
        $a
}}
"""


@pytest.mark.unit
def test_list_signatures_verbose_and_duplicate_uuids(tmp_path, capsys):
    rule_uuid = "66666666-6666-6666-6666-666666666666"
    os.makedirs(tmp_path / "yara" / "set")
    (tmp_path / "yara" / "set" / "first.yar").write_text(_yara_rule("first_rule", rule_uuid))
    (tmp_path / "yara" / "set" / "second.yar").write_text(_yara_rule("second_rule", rule_uuid))

    args = _list_args(["yara"])
    args.verbose = True
    with pytest.raises(SystemExit) as excinfo:
        cli_list_signatures(args)

    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "first_rule" in captured.out and "second_rule" in captured.out
    assert f"2 yara signatures from {tmp_path / 'yara'}" in captured.err
    assert "2 signatures (yara=2)" in captured.err
    assert f"WARNING: yara uuid {rule_uuid} is used by more than one signature" in captured.err


@pytest.mark.unit
def test_list_signatures_with_none_loaded(capsys):
    with pytest.raises(SystemExit):
        cli_list_signatures(_list_args(["observable_modifier"]))

    assert capsys.readouterr().err.endswith("0 signatures\n")


#
# ace signatures build-db
#

@pytest.fixture
def snort_build(monkeypatch):
    """Records the path build_signature_db was asked to load, and returns what it is told to."""
    calls = []
    result = {"value": None}

    def build(signature_path):
        calls.append(signature_path)
        if isinstance(result["value"], Exception):
            raise result["value"]
        return result["value"]

    monkeypatch.setattr("saq.modules.snort.build_signature_db", build)
    return calls, result


@pytest.mark.unit
def test_build_db_uses_the_configured_signature_path(snort_build, monkeypatch):
    calls, result = snort_build
    monkeypatch.setattr(
        get_config().get_analysis_module_config(ANALYSIS_MODULE_SNORT_SIGNATURE_ANALYSIS_V1),
        "signature_path", "/configured/snort.rules")
    result["value"] = object()

    with pytest.raises(SystemExit) as excinfo:
        build_signature_db(argparse.Namespace(signature_path=None))

    assert excinfo.value.code == 0
    assert calls == ["/configured/snort.rules"]


@pytest.mark.unit
def test_build_db_signature_path_override(snort_build):
    calls, result = snort_build
    result["value"] = object()

    with pytest.raises(SystemExit) as excinfo:
        build_signature_db(argparse.Namespace(signature_path="/override/snort.rules"))

    assert excinfo.value.code == 0
    assert calls == ["/override/snort.rules"]


@pytest.mark.unit
def test_build_db_failure_is_logged_with_its_traceback(snort_build, caplog):
    _, result = snort_build
    result["value"] = FileNotFoundError("no such file")

    with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as excinfo:
        build_signature_db(argparse.Namespace(signature_path="/missing/snort.rules"))

    assert excinfo.value.code == 1
    [record] = [r for r in caplog.records if "unable to rebuild suricata db" in r.getMessage()]
    assert "/missing/snort.rules" in record.getMessage()
    assert record.exc_info is not None


@pytest.mark.unit
def test_build_db_refused_by_the_lock_fails(snort_build, caplog):
    _, result = snort_build
    # what build_signature_db returns when another rebuild holds the lock
    result["value"] = False

    with pytest.raises(SystemExit) as excinfo:
        build_signature_db(argparse.Namespace(signature_path="/rules/snort.rules"))

    assert excinfo.value.code == 1
    assert "another rebuild holds the lock" in caplog.text
