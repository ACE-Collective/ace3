import os

import pytest

from saq.configuration.config import get_service_config
from saq.constants import SERVICE_YARA_SCANNER
from saq.signatures.builtin import SIGNATURE_VERSION_UNKNOWN
from saq.signatures.yara_inventory import get_yara_inventory
from saq.signatures.yara_meta import is_qa_signature

QA_RULE_UUID = "5a0c7f1e-1c43-4a39-8d8e-2f1b3c4d5e6f"
PLAIN_RULE_UUID = "6b1d8a2f-2d54-4b4a-9e9f-3a2c4d5e6f70"
DISABLED_QA_UUID = "7c2e9b3a-3e65-4c5b-8fa0-4b3d5e6f7081"

RULES = f"""\
rule qa_rule
{{
    meta:
        uuid = "{QA_RULE_UUID}"
        modifiers = "qa"
    strings:
        $a = "qa"
    condition:
        $a
}}

rule plain_rule
{{
    meta:
        uuid = "{PLAIN_RULE_UUID}"
    strings:
        $a = "plain"
    condition:
        $a
}}

rule disabled_qa_rule
{{
    meta:
        uuid = "{DISABLED_QA_UUID}"
        modifiers = "no_alert,qa"
        enabled = "false"
    strings:
        $a = "disabled"
    condition:
        $a
}}

rule no_uuid_rule
{{
    strings:
        $a = "none"
    condition:
        $a
}}
"""


@pytest.fixture
def signature_dir(tmp_path, monkeypatch) -> str:
    """A signature_dir with one rule set, outside any git repo."""
    root = tmp_path / "yara"
    (root / "unittest").mkdir(parents=True)
    (root / "unittest" / "rules.yar").write_text(RULES)
    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "signature_dir", str(root))
    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "git_repo_dirs", [])
    return str(root)


def _rules_file(signature_dir: str) -> str:
    return os.path.join(signature_dir, "unittest", "rules.yar")


@pytest.mark.integration
def test_inventory_lists_rules_with_a_uuid(signature_dir):
    inventory = get_yara_inventory(max_age_seconds=0)

    assert inventory.error is None
    assert set(inventory.by_uuid) == {QA_RULE_UUID, PLAIN_RULE_UUID, DISABLED_QA_UUID}
    assert inventory.by_uuid[DISABLED_QA_UUID].enabled is False
    assert inventory.by_uuid[QA_RULE_UUID].version == SIGNATURE_VERSION_UNKNOWN
    assert inventory.by_uuid[PLAIN_RULE_UUID].content_hash
    assert {s.name for s in inventory.by_uuid.values() if is_qa_signature(s)} == {"qa_rule", "disabled_qa_rule"}


@pytest.mark.integration
def test_inventory_sees_changed_rule_files(signature_dir):
    assert is_qa_signature(get_yara_inventory(max_age_seconds=0).by_uuid[QA_RULE_UUID])

    with open(_rules_file(signature_dir), "w") as fp:
        fp.write(RULES.replace('modifiers = "qa"', 'modifiers = "no_alert"'))

    assert not is_qa_signature(get_yara_inventory(max_age_seconds=0).by_uuid[QA_RULE_UUID])


@pytest.mark.integration
def test_inventory_is_cached_for_its_max_age(signature_dir):
    first = get_yara_inventory(max_age_seconds=3600)
    os.remove(_rules_file(signature_dir))

    # young enough for this caller: the cached one
    assert get_yara_inventory(max_age_seconds=3600) is first
    # too old for this one: rebuilt
    assert get_yara_inventory(max_age_seconds=0).by_uuid == {}


@pytest.mark.integration
def test_the_qa_rule_wins_a_shared_uuid(signature_dir):
    # the plain rule comes first, so the qa rule has to win, not just be found first
    shared = f"""\
rule plain_rule
{{
    meta:
        uuid = "{QA_RULE_UUID}"
    strings:
        $a = "plain"
    condition:
        $a
}}

rule qa_rule
{{
    meta:
        uuid = "{QA_RULE_UUID}"
        modifiers = "qa"
    strings:
        $a = "qa"
    condition:
        $a
}}
"""
    with open(_rules_file(signature_dir), "w") as fp:
        fp.write(shared)

    assert get_yara_inventory(max_age_seconds=0).by_uuid[QA_RULE_UUID].name == "qa_rule"


@pytest.mark.integration
def test_inventory_reports_a_missing_signature_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "signature_dir", str(tmp_path / "nope"))

    inventory = get_yara_inventory(max_age_seconds=0)

    assert inventory.by_uuid == {}
    assert "unable to load yara signatures" in inventory.error
