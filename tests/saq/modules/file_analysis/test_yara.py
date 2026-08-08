import pytest

import yara_scanner

from saq.modules.file_analysis.yara import _yara_detection_signature
from saq.signatures.builtin import SIGNATURE_VERSION_UNKNOWN, YARA_RULE_MATCH


@pytest.mark.unit
def test_basic_yara_scan(datadir):
    scanner = yara_scanner.YaraScanner(signature_dir=str(datadir / "yara_rules"))
    scanner.load_rules()
    target_file = str(datadir / "sample.target")
    result = scanner.scan(target_file)


@pytest.mark.unit
def test_yara_detection_signature_with_uuid_and_commit():
    # rule with a uuid meta + a resolved git commit
    result = {"rule": "r", "meta": {"uuid": "rule-uuid-1"}, "commit": "abc123"}
    sig_uuid, sig_version = _yara_detection_signature(result)
    assert sig_uuid == "rule-uuid-1"
    assert sig_version == "abc123"


@pytest.mark.unit
def test_yara_detection_signature_no_commit_is_unknown():
    # rule not from a git repo -> commit is None -> unknown version
    result = {"rule": "r", "meta": {"uuid": "rule-uuid-1"}, "commit": None}
    sig_uuid, sig_version = _yara_detection_signature(result)
    assert sig_uuid == "rule-uuid-1"
    assert sig_version == SIGNATURE_VERSION_UNKNOWN


@pytest.mark.unit
def test_yara_detection_signature_no_uuid_falls_back(caplog):
    # warn-but-detect: no uuid meta -> built-in YARA_RULE_MATCH fallback + warning
    import logging
    result = {"rule": "r", "meta": {}, "commit": "abc123"}
    with caplog.at_level(logging.WARNING):
        sig_uuid, sig_version = _yara_detection_signature(result)
    assert sig_uuid == YARA_RULE_MATCH.uuid
    assert sig_version == "abc123"
    assert any("has no uuid meta" in r.message for r in caplog.records)
