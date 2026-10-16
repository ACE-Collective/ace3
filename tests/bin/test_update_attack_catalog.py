"""Tests for bin/update-attack-catalog, which builds the ATT&CK extract SVS coverage reads
(docs/SVS_COVERAGE.md, *The ATT&CK release*), against a synthesized STIX bundle."""

import importlib.machinery
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "bin" / "update-attack-catalog"

pytestmark = pytest.mark.unit


def _load_script():
    # no .py extension, so the loader has to be named explicitly
    loader = importlib.machinery.SourceFileLoader("update_attack_catalog", str(SCRIPT_PATH))
    spec = importlib.util.spec_from_file_location("update_attack_catalog", SCRIPT_PATH, loader=loader)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


script = _load_script()


def _refs(external_id):
    return [{"source_name": "mitre-attack", "external_id": external_id, "url": "https://attack.mitre.org/"}]


def _tactic(external_id, shortname, name):
    return {"type": "x-mitre-tactic", "id": f"x-mitre-tactic--{shortname}", "name": name,
            "x_mitre_shortname": shortname, "external_references": _refs(external_id)}


def _technique(external_id, name, phases=("execution",), platforms=("Windows",), **fields):
    return {"type": "attack-pattern", "id": f"attack-pattern--{external_id}", "name": name,
            "external_references": _refs(external_id), "x_mitre_domains": ["enterprise-attack"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": phase} for phase in phases],
            "x_mitre_platforms": list(platforms), **fields}


def _relationship(kind, source, target):
    return {"type": "relationship", "id": f"relationship--{source}-{kind}-{target}", "relationship_type": kind,
            "source_ref": f"attack-pattern--{source}", "target_ref": f"attack-pattern--{target}"}


def _bundle(*extra, version="20.0"):
    objects = [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "name": "Enterprise ATT&CK",
         "x_mitre_version": version},
        _tactic("TA0002", "execution", "Execution"),
        _tactic("TA0003", "persistence", "Persistence"),
        _tactic("TA0005", "stealth", "Stealth"),
        # the matrix orders the tactics, not their ids
        {"type": "x-mitre-matrix", "id": "x-mitre-matrix--1", "name": "Enterprise ATT&CK",
         "tactic_refs": ["x-mitre-tactic--persistence", "x-mitre-tactic--execution", "x-mitre-tactic--stealth"]},
        _technique("T1059", "Command and Scripting Interpreter", platforms=("Linux", "Windows", "macOS")),
        _technique("T1059.001", "PowerShell", x_mitre_is_subtechnique=True),
        _relationship("subtechnique-of", "T1059.001", "T1059"),
        # a sub-technique the bundle doesn't relate to its parent
        _technique("T1059.003", "Windows Command Shell", x_mitre_is_subtechnique=True),
        _technique("T1547", "Boot or Logon Autostart Execution", phases=("persistence", "execution"),
                   kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
                                      {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
                                      {"kill_chain_name": "lockheed", "phase_name": "installation"}]),
        _technique("T1564", "Hide Artifacts", phases=("stealth",), platforms=("Office 365", "Azure AD", "Network")),
        _technique("T1099", "Timestomp", x_mitre_deprecated=True),
        # T1150 was revoked by T1500, which was revoked by T1647
        _technique("T1150", "Plist Modification", revoked=True),
        _technique("T1500", "Compile After Delivery", revoked=True),
        _technique("T1647", "Plist File Modification", platforms=("macOS",)),
        _relationship("revoked-by", "T1150", "T1500"),
        _relationship("revoked-by", "T1500", "T1647"),
        # an attack-pattern from another domain, and one without an ATT&CK id
        {**_technique("T1400", "Mobile thing"), "x_mitre_domains": ["mobile-attack"]},
        {"type": "attack-pattern", "id": "attack-pattern--noid", "name": "No id", "external_references": []},
        *extra,
    ]
    return json.dumps({"type": "bundle", "id": "bundle--1", "objects": objects}).encode()


def _build(*extra, previous=None, release="v20.0"):
    return script.build(_bundle(*extra), release, "https://example.invalid/enterprise-attack-20.0.json", previous)


def test_parse_release():
    assert script.parse_release("v20.0") == "v20.0"
    assert script.parse_release("20.1") == "v20.1"
    assert script.parse_release("v20") == "v20.0"
    assert script.parse_release(" 18 ") == "v18.0"
    for value in ("latest", "v20.0.1", "../v20", ""):
        with pytest.raises(script.BuildError):
            script.parse_release(value)


def test_the_extract():
    extract = _build()
    assert extract["format"] == script.FORMAT
    assert extract["release"] == "v20.0"
    assert extract["domain"] == "enterprise-attack"
    assert len(extract["source"]["sha256"]) == 64
    assert [tactic["id"] for tactic in extract["tactics"]] == ["TA0003", "TA0002", "TA0005"]
    assert extract["tactics"][0] == {"id": "TA0003", "shortname": "persistence", "name": "Persistence"}

    techniques = extract["techniques"]
    assert set(techniques) == {"T1059", "T1059.001", "T1059.003", "T1547", "T1564", "T1099", "T1647"}
    assert techniques["T1059"] == {"name": "Command and Scripting Interpreter", "parent": None, "tactics": ["TA0002"],
                                   "platforms": ["windows", "linux", "macos"], "deprecated": False}
    assert techniques["T1059.001"]["parent"] == "T1059"
    assert techniques["T1059.003"]["parent"] == "T1059"
    # tactics in the matrix's order; another kill chain's phases are not tactics
    assert techniques["T1547"]["tactics"] == ["TA0003", "TA0002"]
    # old platform names get today's slugs
    assert techniques["T1564"]["platforms"] == ["office-suite", "identity-provider", "network-devices"]
    assert techniques["T1099"]["deprecated"] is True

    # only the platforms some technique has, in display order
    assert [platform["slug"] for platform in extract["platforms"]] == [
        "windows", "linux", "macos", "office-suite", "identity-provider", "network-devices"]
    assert extract["platforms"][3] == {"slug": "office-suite", "name": "Office Suite"}


def test_revocations_are_followed_to_a_current_technique():
    assert _build()["revoked"] == {"T1150": "T1647", "T1500": "T1647"}


def test_a_revocation_cycle_is_an_error():
    with pytest.raises(script.BuildError, match="cycle"):
        _build(_technique("T1001", "A", revoked=True), _technique("T1002", "B", revoked=True),
               _relationship("revoked-by", "T1001", "T1002"), _relationship("revoked-by", "T1002", "T1001"))


def test_a_revocation_without_a_successor_is_left_out(capsys):
    extract = _build(_technique("T1003", "Gone", revoked=True), _technique("T1004", "Gone too", revoked=True),
                     _relationship("revoked-by", "T1004", "T9999"))
    assert "T1003" not in extract["revoked"]
    assert "T1004" not in extract["revoked"]
    assert "T1003 is revoked without a successor" in capsys.readouterr().err


def test_a_revoked_id_that_is_also_current_stays_current(capsys):
    extract = _build({**_technique("T1059", "Old interpreter", revoked=True), "id": "attack-pattern--old-T1059"},
                     {**_relationship("revoked-by", "T1059", "T1647"), "source_ref": "attack-pattern--old-T1059"})
    assert "T1059" in extract["techniques"]
    assert "T1059" not in extract["revoked"]
    assert "the current technique wins" in capsys.readouterr().err


def test_an_unknown_platform_stops_the_build():
    with pytest.raises(script.BuildError, match="'Mainframe', which has no slug"):
        _build(_technique("T1005", "Data from Local System", platforms=("Mainframe",)))


def test_an_unknown_tactic_stops_the_build():
    with pytest.raises(script.BuildError, match="names tactic 'exfiltration'"):
        _build(_technique("T1005", "Data from Local System", phases=("exfiltration",)))


def test_the_bundle_must_be_the_release():
    with pytest.raises(script.BuildError, match="not v20.1"):
        _build(release="v20.1")


def test_a_duplicate_technique_stops_the_build():
    with pytest.raises(script.BuildError, match="T1059 appears twice"):
        _build({**_technique("T1059", "Again"), "id": "attack-pattern--again"})


def test_renames_since_a_previous_extract():
    previous = {"release": "v19.2", "techniques": {"T1059": {"name": "Scripting"}, "T1647": {"name": "Plist File Modification"}}}
    assert _build(previous=previous)["renamed"] == {"T1059": {"from": "Scripting", "previous_release": "v19.2"}}
    assert _build()["renamed"] == {}


def test_main_writes_the_same_bytes_every_time(tmp_path):
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(_bundle())
    out = tmp_path / "attack"
    assert script.main(["20.0", "--input", str(bundle), "--output-dir", str(out)]) == 0
    first = (out / "v20.0.json").read_bytes()
    assert script.main(["v20.0", "--input", str(bundle), "--output-dir", str(out)]) == 0
    assert (out / "v20.0.json").read_bytes() == first
    assert json.loads(first)["source"]["url"].endswith("/enterprise-attack-20.0.json")
    # nothing left behind by the atomic write
    assert [path.name for path in out.iterdir()] == ["v20.0.json"]


def test_main_fails_without_writing(tmp_path, capsys):
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(_bundle(version="19.0"))
    out = tmp_path / "attack"
    assert script.main(["v20.0", "--input", str(bundle), "--output-dir", str(out)]) == 1
    assert not out.exists()
    assert "error: the bundle is ATT&CK" in capsys.readouterr().err
