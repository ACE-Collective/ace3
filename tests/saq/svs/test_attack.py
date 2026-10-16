import json

import pytest
from pydantic import ValidationError

from saq.configuration.config import get_config
from saq.configuration.schema import SVSConfig
from saq.svs import attack_files
from saq.svs.attack import (
    AttackCatalog,
    Resolution,
    TechniqueStatus,
    get_attack_catalog,
    load_attack_catalog,
    normalize_platform,
    normalize_technique_id,
    syntactic_parent,
)
from tests.saq.svs.conftest import ATTACK_EXTRACT as EXTRACT

pytestmark = pytest.mark.unit

@pytest.fixture
def catalog(attack_catalog) -> AttackCatalog:
    return attack_catalog


def test_normalize_technique_id():
    assert normalize_technique_id(" t1059.001 ") == "T1059.001"
    assert normalize_technique_id("T1059") == "T1059"
    for value in ("TA0002", "{{ technique }}", "T105", "T1059.1", "mitre:T1059", ""):
        assert normalize_technique_id(value) is None


def test_syntactic_parent():
    assert syntactic_parent("T1059.001") == "T1059"
    assert syntactic_parent("T1059") is None


def test_normalize_platform():
    assert normalize_platform("windows") == "windows"
    assert normalize_platform(" macOS ") == "macos"
    assert normalize_platform("iaas:aws") == "iaas"
    assert normalize_platform("iaas:gcp") == "iaas"
    assert normalize_platform("azure-ad") == "identity-provider"
    assert normalize_platform("office-365") == "office-suite"
    assert normalize_platform("google-workspace") == "office-suite"
    assert normalize_platform("containers") == "containers"


def test_the_catalog(catalog):
    assert catalog.release == "v99.0"
    assert list(catalog.platforms) == ["windows", "macos"]
    assert catalog.platform_name("macos") == "macOS"
    assert catalog.platform_name("esxi") == "esxi"
    assert [tactic.id for tactic in catalog.tactics] == ["TA0003", "TA0002"]

    technique = catalog.technique("T1547")
    assert technique.name == "Boot or Logon Autostart Execution"
    assert technique.tactics == ("TA0003", "TA0002")
    assert technique.platforms == ("windows",)
    assert technique.status == TechniqueStatus.ACTIVE
    assert catalog.technique("T1099").status == TechniqueStatus.DEPRECATED
    assert catalog.technique("T9999") is None
    assert catalog.renamed["T1059"]["from"] == "Scripting"


def test_resolve(catalog):
    assert catalog.resolve("T1059") == Resolution("T1059", TechniqueStatus.ACTIVE)
    assert catalog.resolve("t1086") == Resolution("T1059.001", TechniqueStatus.ACTIVE, revoked_from="T1086")
    assert catalog.resolve("T1150") == Resolution("T1099", TechniqueStatus.DEPRECATED, revoked_from="T1150")
    assert catalog.resolve("T1234.005") == Resolution("T1234.005", TechniqueStatus.UNKNOWN)
    with pytest.raises(ValueError):
        catalog.resolve("TA0002")


def test_parents_and_children(catalog):
    assert catalog.parent_of("T1059.001") == "T1059"
    assert catalog.parent_of("T1059") is None
    # an id the release doesn't have: its syntax names the parent
    assert catalog.parent_of("T1234.005") == "T1234"
    assert catalog.children_of("T1059") == ("T1059.001", "T1059.002")
    assert catalog.children_of("T1547") == ()


def test_tactics(catalog):
    assert catalog.tactic("TA0002").shortname == "execution"
    assert catalog.tactic("ta0002").id == "TA0002"
    assert catalog.tactic("Persistence").id == "TA0003"
    assert catalog.tactic("stealth") is None
    assert catalog.techniques_in(["TA0003"]) == {"T1547"}
    assert catalog.techniques_in(["TA0002"]) == {"T1059", "T1059.001", "T1059.002", "T1547"}


def test_another_format_is_refused(tmp_path):
    path = tmp_path / "v99.0.json"
    path.write_text(json.dumps({**EXTRACT, "format": 2}))
    with pytest.raises(ValueError, match="rebuild it with bin/update-attack-catalog"):
        load_attack_catalog(path)


def test_the_vendored_release():
    release = get_config().svs.attack_release
    assert attack_files.release_path(release).is_file()
    catalog = get_attack_catalog()
    assert catalog.release == release
    assert catalog is get_attack_catalog(release)
    assert catalog.technique("T1059.001").parent == "T1059"
    assert "windows" in catalog.technique("T1059.001").platforms
    assert catalog.tactic("execution").id == "TA0002"
    # every revoked id leads to a technique of the release, and every parent is one
    assert all(successor in catalog.techniques for successor in catalog.revoked.values())
    assert all(technique.parent in catalog.techniques for technique in catalog.techniques.values() if technique.parent)
    assert set(catalog.platforms) <= {"windows", "linux", "macos", "esxi", "iaas", "containers", "saas",
                                      "office-suite", "identity-provider", "network-devices", "pre"}


def test_attack_release_must_be_vendored(tmp_path, monkeypatch):
    assert SVSConfig().attack_release == get_config().svs.attack_release
    with pytest.raises(ValidationError, match="is not an ATT&CK release name"):
        SVSConfig.model_validate({"attack_release": "../v20.0"})
    with pytest.raises(ValidationError, match="is missing; bin/update-attack-catalog v1.0 builds it"):
        SVSConfig.model_validate({"attack_release": "v1.0"})

    monkeypatch.setattr(attack_files, "ATTACK_DIR", tmp_path)
    (tmp_path / "v1.0.json").write_text(json.dumps(EXTRACT))
    assert SVSConfig.model_validate({"attack_release": "v1.0"}).attack_release == "v1.0"
