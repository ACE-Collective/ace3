import os
from datetime import datetime

import pytest

from saq.configuration.config import get_service_config
from saq.constants import SERVICE_YARA_SCANNER
from saq.database.model import YaraQASignature
from saq.signatures.builtin import SIGNATURE_VERSION_UNKNOWN
from saq.yara_qa.inventory import get_yara_inventory
from saq.yara_qa.listing import QASort, QAStatus, filter_and_sort, merge
from saq.yara_qa.model import YaraInventory

QA_RULE_UUID = "5a0c7f1e-1c43-4a39-8d8e-2f1b3c4d5e6f"
PLAIN_RULE_UUID = "6b1d8a2f-2d54-4b4a-9e9f-3a2c4d5e6f70"
DISABLED_QA_UUID = "7c2e9b3a-3e65-4c5b-8fa0-4b3d5e6f7081"
GONE_UUID = "8d3fac4b-4f76-4d6c-90b1-5c4e6f708192"

RULES = f"""\
rule never_matched_qa_rule
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


def _version_row(signature_uuid: str, version: str, rule_name: str, match_count: int, stored_count: int,
                 last_match_at: datetime) -> YaraQASignature:
    return YaraQASignature(
        signature_uuid=signature_uuid, signature_version=version, rule_name=rule_name, namespace="ns",
        match_count=match_count, stored_count=stored_count, first_match_at=datetime(2026, 1, 1),
        last_match_at=last_match_at)


@pytest.mark.integration
def test_inventory_lists_qa_rules(signature_dir):
    inventory = get_yara_inventory()
    assert inventory.error is None
    assert set(inventory.by_uuid) == {QA_RULE_UUID, PLAIN_RULE_UUID, DISABLED_QA_UUID}
    assert {s.name for s in inventory.qa_signatures} == {"never_matched_qa_rule", "disabled_qa_rule"}
    assert inventory.by_uuid[DISABLED_QA_UUID].enabled is False
    assert inventory.by_uuid[QA_RULE_UUID].version == SIGNATURE_VERSION_UNKNOWN


@pytest.mark.integration
def test_inventory_sees_changed_rule_files(signature_dir):
    assert QA_RULE_UUID in {s.uuid for s in get_yara_inventory().qa_signatures}

    # the tests run with inventory_refresh_seconds 0, so the next call rescans
    with open(os.path.join(signature_dir, "unittest", "rules.yar"), "w") as fp:
        fp.write(RULES.replace('modifiers = "qa"', 'modifiers = "no_alert"'))

    assert QA_RULE_UUID not in {s.uuid for s in get_yara_inventory().qa_signatures}


@pytest.mark.integration
def test_inventory_reports_a_missing_signature_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "signature_dir", str(tmp_path / "nope"))
    inventory = get_yara_inventory()
    assert inventory.by_uuid == {}
    assert "unable to load yara signatures" in inventory.error


@pytest.mark.integration
def test_merge_statuses(signature_dir):
    inventory = get_yara_inventory()
    rows = [
        # a rule in qa mode with matches under two versions
        _version_row(DISABLED_QA_UUID, "v1", "disabled_qa_rule", 5, 2, datetime(2026, 9, 1)),
        _version_row(DISABLED_QA_UUID, "v2", "disabled_qa_rule_renamed", 3, 1, datetime(2026, 9, 20)),
        # a rule that left qa mode
        _version_row(PLAIN_RULE_UUID, "v1", "plain_rule", 7, 3, datetime(2026, 8, 1)),
        # a rule that left the repository
        _version_row(GONE_UUID, "v1", "gone_rule", 1, 1, datetime(2026, 7, 1)),
    ]
    signatures = {s.signature_uuid: s for s in merge(inventory, rows)}
    assert set(signatures) == {QA_RULE_UUID, DISABLED_QA_UUID, PLAIN_RULE_UUID, GONE_UUID}

    never = signatures[QA_RULE_UUID]
    assert (never.status, never.match_count, never.stored_count, never.version_count) == (QAStatus.QA, 0, 0, 0)
    assert never.last_match_at is None

    disabled = signatures[DISABLED_QA_UUID]
    assert disabled.status == QAStatus.QA
    assert disabled.enabled is False
    assert (disabled.match_count, disabled.stored_count, disabled.version_count) == (8, 3, 2)
    assert [v.signature_version for v in disabled.versions] == ["v2", "v1"]
    assert disabled.last_match_at == datetime(2026, 9, 20)
    assert disabled.first_match_at == datetime(2026, 1, 1)

    assert signatures[PLAIN_RULE_UUID].status == QAStatus.NOT_QA
    assert signatures[PLAIN_RULE_UUID].name == "plain_rule"

    gone = signatures[GONE_UUID]
    assert (gone.status, gone.name, gone.enabled, gone.current_version) == (QAStatus.MISSING, "gone_rule", None, None)


@pytest.mark.unit
def test_filter_and_sort():
    rows = [
        _version_row("u1", "v1", "bravo", 5, 1, datetime(2026, 9, 1)),
        _version_row("u2", "v1", "alpha", 9, 1, datetime(2026, 8, 1)),
        _version_row("u3", "v1", "charlie", 1, 1, datetime(2026, 9, 5)),
    ]
    signatures = merge(YaraInventory(), rows)
    assert all(s.status == QAStatus.MISSING for s in signatures)

    assert [s.name for s in filter_and_sort(signatures)] == ["alpha", "bravo", "charlie"]
    assert [s.name for s in filter_and_sort(signatures, sort=QASort.MATCH_COUNT, descending=True)] == ["alpha", "bravo", "charlie"]
    assert [s.name for s in filter_and_sort(signatures, sort=QASort.LAST_MATCH, descending=True)] == ["charlie", "bravo", "alpha"]
    assert [s.name for s in filter_and_sort(signatures, q="RAV")] == ["bravo"]
    assert [s.name for s in filter_and_sort(signatures, q="u3")] == ["charlie"]
    assert filter_and_sort(signatures, status=QAStatus.QA) == []
    assert filter_and_sort(signatures, has_matches=False) == []
