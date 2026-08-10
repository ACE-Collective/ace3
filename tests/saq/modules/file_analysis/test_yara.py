import os
import subprocess

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


UUID_RULE = """\
rule signature_version_rule
{
    meta:
        uuid = "7d3f5a21-9c48-4d6b-8e0a-1f2b3c4d5e6f"

    strings:
        $a = "signature version marker"

    condition:
        $a
}
"""


def _init_repo_with_commit(path: str) -> str:
    """init a git repo at path with one commit, returns the HEAD sha"""
    env = dict(os.environ)
    env["GIT_AUTHOR_NAME"] = env["GIT_COMMITTER_NAME"] = "test"
    env["GIT_AUTHOR_EMAIL"] = env["GIT_COMMITTER_EMAIL"] = "test@example.com"
    subprocess.run(["git", "init", path], check=True, capture_output=True)
    subprocess.run(["git", "-C", path, "add", "-A"], check=True, capture_output=True, env=env)
    subprocess.run(["git", "-C", path, "commit", "-m", "rules"], check=True, capture_output=True, env=env)
    return subprocess.run(["git", "-C", path, "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip()


@pytest.mark.unit
def test_declared_git_repo_dir_yields_a_real_signature_version(tmp_path):
    """End to end over the scanner: a rule directory declared in git_repo_dirs is a
    *subdirectory* of the repo (signatures/yara/bv, the layout ACE actually uses),
    and a match on its rules carries the repo's commit rather than "unknown"."""
    repo = str(tmp_path / "signatures")
    signature_dir = os.path.join(repo, "yara")
    rule_dir = os.path.join(signature_dir, "bv")
    os.makedirs(rule_dir)
    with open(os.path.join(rule_dir, "rules.yar"), "w") as fp:
        fp.write(UUID_RULE)

    sha = _init_repo_with_commit(repo)

    scanner = yara_scanner.YaraScanner(signature_dir=signature_dir, git_repo_dirs=["bv"])
    scanner.load_rules()
    assert scanner.scan_data(b"signature version marker")

    sig_uuid, sig_version = _yara_detection_signature(scanner.scan_results[0])
    assert sig_uuid == "7d3f5a21-9c48-4d6b-8e0a-1f2b3c4d5e6f"
    assert sig_version == sha


@pytest.mark.unit
def test_undeclared_rule_dir_still_scans_without_a_version(tmp_path):
    """The same layout with nothing declared: rules still match - losing the
    declaration costs a version stamp, not the detection."""
    repo = str(tmp_path / "signatures")
    signature_dir = os.path.join(repo, "yara")
    rule_dir = os.path.join(signature_dir, "bv")
    os.makedirs(rule_dir)
    with open(os.path.join(rule_dir, "rules.yar"), "w") as fp:
        fp.write(UUID_RULE)

    _init_repo_with_commit(repo)

    scanner = yara_scanner.YaraScanner(signature_dir=signature_dir)
    scanner.load_rules()
    assert scanner.scan_data(b"signature version marker")

    _, sig_version = _yara_detection_signature(scanner.scan_results[0])
    assert sig_version == SIGNATURE_VERSION_UNKNOWN
