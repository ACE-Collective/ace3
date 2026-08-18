"""tests for the signature inventory loaders

the rule content here is synthesized, not copied out of the signatures repo -
that repo holds customer data and this one is public. the fixtures reproduce
the layouts each loader has to mirror, nothing more."""

import hashlib
import logging
import os
import subprocess

import pytest

from saq.environment import get_base_dir
from saq.signatures.builtin import BUILTIN_SIGNATURES, SIGNATURE_VERSION_UNKNOWN
from saq.signatures.loaders import (
    load_builtin_signatures,
    load_hunt_signatures,
    load_observable_modifier_signatures,
    load_signatures,
    load_yara_signatures,
)
from saq.signatures.loaders.builtin import BUILTIN_SOURCE_PATH
from saq.signatures.model import SignatureType

TEST_GIT_REMOTE = "git@example.com:atu/test-signatures.git"

YARA_RULES = """\
rule tracked_rule: phishing smishing
{
    meta:
        uuid = "0dd9b95c-6b52-4c6f-9d4c-b0e30d6e1b1f"
        author = "unittest"
        description = "a rule that can be tracked"
        mitre_attack = "T1566.004, T1566.003"
        meta_tags = "type=document.html.phishkit"

    strings:
        $a = "tracked"

    condition:
        $a
}

rule second_tracked_rule
{
    meta:
        uuid = "1e1c7d3a-8a2e-4a1f-9f0f-2b6a0f8a2e11"

    strings:
        $a = "second"

    condition:
        $a
}

rule untracked_rule
{
    meta:
        description = "no uuid meta, so it cannot be tracked"

    strings:
        $a = "untracked"

    condition:
        $a
}
"""


def _other_rule(name: str, rule_uuid: str) -> str:
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


HUNT_INCLUDE = """\
rule:
  type: test
  frequency: 00:10:00
  tags:
    - mitre:T1059.001
"""

HUNT_RULE = """\
include:
  - includes/common.include.yaml

rule:
  uuid: 6a6d1b4c-9e0b-4c4f-9a1a-7d2f0a3b5c6d
  name: test hunt
  enabled: true
  description: a hunt used to test the signature loader
  alert_type: test - hunt
  tags:
    - atu:detection
"""

HUNT_TEMPLATE = """\
rule:
  uuid: 11111111-1111-1111-1111-111111111111
  name: template hunt
  type: test
  enabled: false
  description: the starting point for a new hunt, not a hunt
  alert_type: test - template
  frequency: 00:10:00
"""

OBSERVABLE_MODIFIER_RULES = """\
rules:
  - name: adds a detection point
    uuid: 8f2b6d5e-4c3a-4b2d-9e1f-0a1b2c3d4e5f
    description: the only rule here that is a signature
    conditions:
      observable_types: [url]
      value_pattern: 'example\\.com'
    actions:
      add_tags: [suspect_url, suspect_url]
      add_detection_points: ["suspect url observed"]

  - name: adds no detection point
    uuid: 9a3c7e6f-5d4b-4c3e-8f2a-1b2c3d4e5f60
    conditions:
      observable_types: [file]
    actions:
      add_directives: [extract_iocs]

  - name: has no uuid but does detect
    conditions:
      observable_types: [url]
    actions:
      add_detection_points: ["cannot be tracked"]
"""


def _write(path: str, content: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fp:
        fp.write(content)


def _git(repo: str, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", repo] + list(args),
        text=True, capture_output=True, check=True).stdout.strip()


def _commit(repo: str, message: str = "signatures") -> str:
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=unittest", "-c", "user.email=unittest@localhost",
         "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _populate(root: str):
    """Writes the layout each loader has to traverse.

    yara/         the signature_dir: one subdirectory per rule set, plus a loose
                  rule file and a generated export directory that must be ignored
    hunts/        a hunt rule directory with an includes/ subdirectory
    rules/        the observable modifier ruleset, a single file
    """
    _write(os.path.join(root, "yara", "bv", "rules.yar"), YARA_RULES)
    _write(os.path.join(root, "yara", "bv", "nested", "nested.yar"),
           _other_rule("nested_rule", "22222222-2222-2222-2222-222222222222"))
    _write(os.path.join(root, "yara", "loose.yar"),
           _other_rule("loose_rule", "33333333-3333-3333-3333-333333333333"))
    _write(os.path.join(root, "yara", "observable_export", "url.yar"),
           _other_rule("generated_rule", "44444444-4444-4444-4444-444444444444"))

    _write(os.path.join(root, "hunts", "includes", "common.include.yaml"), HUNT_INCLUDE)
    _write(os.path.join(root, "hunts", "test_hunt.yaml"), HUNT_RULE)
    _write(os.path.join(root, "hunts", "template.yaml"), HUNT_TEMPLATE)
    _write(os.path.join(root, "hunts", "shared.include.yaml"), HUNT_INCLUDE)

    _write(os.path.join(root, "rules", "observable_modifier_rules.yaml"), OBSERVABLE_MODIFIER_RULES)


@pytest.fixture
def signature_repo(tmp_path) -> str:
    """A throwaway git repo laid out the way the real signatures repo is."""
    repo = str(tmp_path / "signatures")
    os.makedirs(repo)
    _git(repo, "init", "-b", "main")
    _git(repo, "remote", "add", "origin", TEST_GIT_REMOTE)
    _populate(repo)
    _commit(repo)
    return repo


@pytest.fixture
def signature_dir(tmp_path) -> str:
    """The same layout, in a directory that is not a git repo."""
    root = str(tmp_path / "loose")
    os.makedirs(root)
    _populate(root)
    return root


def _yara_dir(root: str) -> str:
    return os.path.join(root, "yara")


def _hunt_dir(root: str) -> str:
    return os.path.join(root, "hunts")


def _rules_file(root: str) -> str:
    return os.path.join(root, "rules", "observable_modifier_rules.yaml")


#
# yara
#

@pytest.mark.unit
def test_load_yara_signatures(signature_repo):
    signatures = load_yara_signatures(_yara_dir(signature_repo))

    # the rule with no uuid meta is skipped, the other two still load
    assert [s.name for s in signatures] == ["second_tracked_rule", "tracked_rule"]

    tracked = [s for s in signatures if s.name == "tracked_rule"][0]
    assert tracked.uuid == "0dd9b95c-6b52-4c6f-9d4c-b0e30d6e1b1f"
    assert tracked.type == SignatureType.YARA
    assert tracked.version == _git(signature_repo, "rev-parse", "HEAD")
    assert tracked.git_remote == TEST_GIT_REMOTE
    assert tracked.source_path == "yara/bv/rules.yar"

    # native rule tags merged with mitre_attack, sorted and deduplicated
    assert tracked.tags == ("mitre:T1566.003", "mitre:T1566.004", "phishing", "smishing")


@pytest.mark.unit
def test_yara_traversal_matches_the_scanner(signature_repo):
    """The scanner loads signature_dir/<rule set>/*.yar and nothing else."""
    names = [s.name for s in load_yara_signatures(_yara_dir(signature_repo))]

    # a .yar loose in the signature_dir is not in any rule set
    assert "loose_rule" not in names
    # the scanner does not recurse into a rule directory
    assert "nested_rule" not in names
    # generated observable export rules are not authored signatures
    assert "generated_rule" not in names


@pytest.mark.unit
def test_yara_rule_directories_resolve_their_own_version(signature_repo, tmp_path):
    """A rule directory that is its own git repo gets its own commit, since the
    signature_dir layout exists to let separate rule repos sit side by side."""
    sibling = os.path.join(_yara_dir(signature_repo), "sibling")
    _write(os.path.join(sibling, "rules.yar"),
           _other_rule("sibling_rule", "55555555-5555-5555-5555-555555555555"))
    _git(sibling, "init", "-b", "main")
    _git(sibling, "remote", "add", "origin", "git@example.com:atu/sibling.git")
    sibling_sha = _commit(sibling)

    by_name = {s.name: s for s in load_yara_signatures(_yara_dir(signature_repo))}

    assert by_name["sibling_rule"].version == sibling_sha
    assert by_name["sibling_rule"].git_remote == "git@example.com:atu/sibling.git"
    assert by_name["tracked_rule"].version == _git(signature_repo, "rev-parse", "HEAD")
    assert by_name["tracked_rule"].version != sibling_sha


@pytest.mark.unit
def test_yara_git_repo_dirs_declaration_is_mirrored(signature_repo):
    """Given the service's git_repo_dirs, the inventory versions exactly the rule
    directories the scanner does - so it reports what a detection would record."""
    sibling = os.path.join(_yara_dir(signature_repo), "sibling")
    _write(os.path.join(sibling, "rules.yar"),
           _other_rule("sibling_rule", "55555555-5555-5555-5555-555555555555"))
    _commit(signature_repo, "add sibling")

    by_name = {s.name: s for s in load_yara_signatures(_yara_dir(signature_repo), ["bv"])}

    declared = by_name["tracked_rule"]
    assert declared.version == _git(signature_repo, "rev-parse", "HEAD")
    assert declared.git_remote == TEST_GIT_REMOTE

    undeclared = by_name["sibling_rule"]
    assert undeclared.version == SIGNATURE_VERSION_UNKNOWN
    assert undeclared.git_remote is None
    # the path stays repo relative even without a version
    assert undeclared.source_path == "yara/sibling/rules.yar"


@pytest.mark.unit
def test_yara_git_repo_dirs_entry_forms(signature_repo):
    """An entry may be a subdirectory name, a relative path or an absolute one -
    the same forms YaraScanner._resolve_signature_subdir accepts."""
    yara_dir = _yara_dir(signature_repo)
    versions = set()
    for entry in ("bv", "./bv", os.path.join(yara_dir, "bv")):
        versions.add(load_yara_signatures(yara_dir, [entry])[0].version)

    assert versions == {_git(signature_repo, "rev-parse", "HEAD")}


@pytest.mark.unit
def test_yara_empty_git_repo_dirs_versions_nothing(signature_repo):
    signatures = load_yara_signatures(_yara_dir(signature_repo), [])

    assert signatures
    assert all(s.version == SIGNATURE_VERSION_UNKNOWN for s in signatures)
    assert all(s.git_remote is None for s in signatures)


@pytest.mark.unit
def test_yara_content_hash_is_per_rule(signature_repo):
    signatures = load_yara_signatures(_yara_dir(signature_repo))
    hashes = {s.content_hash for s in signatures}

    # two rules in one file are two signatures with two different hashes...
    assert len(hashes) == 2

    # ...and neither is the hash of the file they share
    assert hashlib.sha256(YARA_RULES.encode()).hexdigest() not in hashes

    # the hash is over the rule as authored: `rule second_tracked_rule` through
    # its closing brace, and nothing of the rules on either side of it
    lines = YARA_RULES.splitlines(keepends=True)
    start = lines.index("rule second_tracked_rule\n")
    stop = start + lines[start:].index("}\n") + 1
    expected = hashlib.sha256("".join(lines[start:stop]).encode()).hexdigest()
    assert [s for s in signatures if s.name == "second_tracked_rule"][0].content_hash == expected


@pytest.mark.unit
def test_yara_requires_a_directory(signature_repo):
    with pytest.raises(NotADirectoryError):
        load_yara_signatures(os.path.join(_yara_dir(signature_repo), "loose.yar"))


#
# hunts
#

@pytest.mark.unit
def test_load_hunt_signatures(signature_repo):
    signatures = load_hunt_signatures(_hunt_dir(signature_repo))

    # template.yaml, the *.include.yaml and the includes/ subdirectory are not hunts
    assert len(signatures) == 1

    hunt = signatures[0]
    assert hunt.name == "test hunt"
    assert hunt.uuid == "6a6d1b4c-9e0b-4c4f-9a1a-7d2f0a3b5c6d"
    assert hunt.type == SignatureType.HUNT
    assert hunt.version == _git(signature_repo, "rev-parse", "HEAD")
    assert hunt.git_remote == TEST_GIT_REMOTE
    assert hunt.source_path == "hunts/test_hunt.yaml"

    # tags from the hunt itself and from the file it includes
    assert hunt.tags == ("atu:detection", "mitre:T1059.001")

    # a hunt is one file, so the hash is the file
    assert hunt.content_hash == hashlib.sha256(HUNT_RULE.encode()).hexdigest()


@pytest.mark.unit
def test_hunt_subdirectories_are_not_scanned(signature_repo):
    """The hunter scans a rule directory, not a tree - a hunt sitting in a
    subdirectory of one is not loaded."""
    _write(os.path.join(_hunt_dir(signature_repo), "nested", "nested_hunt.yaml"),
           HUNT_RULE.replace("include:\n  - includes/common.include.yaml\n\n", "")
                    .replace("test hunt", "nested hunt"))

    assert [s.name for s in load_hunt_signatures(_hunt_dir(signature_repo))] == ["test hunt"]


@pytest.mark.unit
def test_hunt_git_dir_declaration_is_mirrored(signature_repo):
    """HuntManager versions hunts by the git_dir configured alongside their
    rule_dir, so the inventory has to do the same."""
    hunt_dir = _hunt_dir(signature_repo)
    head = _git(signature_repo, "rev-parse", "HEAD")

    declared = load_hunt_signatures(hunt_dir, git_dirs=[signature_repo])[0]
    assert declared.version == head
    assert declared.git_remote == TEST_GIT_REMOTE

    # a rule_dir with no git_dir configured is what a detection records as
    # unknown, even though it is sitting in a repo
    undeclared = load_hunt_signatures(hunt_dir, git_dirs=[])[0]
    assert undeclared.version == SIGNATURE_VERSION_UNKNOWN
    assert undeclared.git_remote is None
    # the path stays repo relative even without a version
    assert undeclared.source_path == "hunts/test_hunt.yaml"

    # omitting the declaration entirely falls back to the enclosing repo
    assert load_hunt_signatures(hunt_dir)[0].version == head


@pytest.mark.unit
def test_hunt_git_dir_that_does_not_contain_the_rules(signature_repo, tmp_path, caplog):
    other_repo = str(tmp_path / "other")
    os.makedirs(other_repo)
    _git(other_repo, "init", "-b", "main")
    _write(os.path.join(other_repo, "README"), "other\n")
    _commit(other_repo)

    with caplog.at_level(logging.ERROR):
        signatures = load_hunt_signatures(_hunt_dir(signature_repo), git_dirs=[other_repo])

    assert signatures[0].version == SIGNATURE_VERSION_UNKNOWN
    assert signatures[0].git_remote is None
    assert any("does not contain" in record.getMessage() for record in caplog.records)


@pytest.mark.unit
def test_hunt_requires_a_directory(signature_repo):
    with pytest.raises(NotADirectoryError):
        load_hunt_signatures(os.path.join(_hunt_dir(signature_repo), "test_hunt.yaml"))


#
# observable modifier rules
#

@pytest.mark.unit
def test_load_observable_modifier_signatures(signature_repo):
    signatures = load_observable_modifier_signatures(_rules_file(signature_repo))

    # only the rule that adds a detection point, and not the one missing a uuid
    assert len(signatures) == 1

    rule = signatures[0]
    assert rule.name == "adds a detection point"
    assert rule.uuid == "8f2b6d5e-4c3a-4b2d-9e1f-0a1b2c3d4e5f"
    assert rule.type == SignatureType.OBSERVABLE_MODIFIER
    assert rule.version == _git(signature_repo, "rev-parse", "HEAD")
    assert rule.git_remote == TEST_GIT_REMOTE
    assert rule.source_path == "rules/observable_modifier_rules.yaml"
    assert rule.tags == ("suspect_url",)

    # the hash covers the rule, not the file it shares with the other two
    assert rule.content_hash != hashlib.sha256(OBSERVABLE_MODIFIER_RULES.encode()).hexdigest()


@pytest.mark.unit
def test_observable_modifier_hash_ignores_other_rules(signature_repo):
    before = load_observable_modifier_signatures(_rules_file(signature_repo))[0]

    _write(_rules_file(signature_repo),
           OBSERVABLE_MODIFIER_RULES.replace("add_directives: [extract_iocs]",
                                             "add_directives: [extract_iocs, crawl]"))

    after = load_observable_modifier_signatures(_rules_file(signature_repo))[0]
    assert after.content_hash == before.content_hash


@pytest.mark.unit
def test_observable_modifier_git_dir_declaration_is_mirrored(signature_repo):
    """ObservableModifierAnalyzer versions its rules by the configured git_dir,
    so the inventory has to do the same."""
    rules_file = _rules_file(signature_repo)
    head = _git(signature_repo, "rev-parse", "HEAD")

    declared = load_observable_modifier_signatures(rules_file, git_dirs=[signature_repo])[0]
    assert declared.version == head
    assert declared.git_remote == TEST_GIT_REMOTE

    undeclared = load_observable_modifier_signatures(rules_file, git_dirs=[])[0]
    assert undeclared.version == SIGNATURE_VERSION_UNKNOWN
    assert undeclared.git_remote is None
    assert undeclared.source_path == "rules/observable_modifier_rules.yaml"

    assert load_observable_modifier_signatures(rules_file)[0].version == head


@pytest.mark.unit
def test_observable_modifier_requires_a_file(signature_repo):
    with pytest.raises(FileNotFoundError):
        load_observable_modifier_signatures(os.path.join(signature_repo, "rules"))


@pytest.mark.unit
def test_observable_modifier_file_without_rules(signature_repo):
    path = os.path.join(signature_repo, "rules", "not_a_ruleset.yaml")
    _write(path, "some_other_config: true\n")

    assert load_observable_modifier_signatures(path) == []


#
# built-ins
#

@pytest.mark.unit
def test_load_builtin_signatures(monkeypatch):
    monkeypatch.setenv("ACE_VERSION", "3.0.90")
    signatures = load_builtin_signatures()

    assert len(signatures) == len(BUILTIN_SIGNATURES)
    assert {s.uuid for s in signatures} == set(BUILTIN_SIGNATURES)
    assert all(s.type == SignatureType.BUILTIN for s in signatures)
    # the version has to be what DetectionPoint stamps, so the rows join
    assert all(s.version == "3.0.90" for s in signatures)
    assert all(s.git_remote is None for s in signatures)
    assert all(s.source_path == BUILTIN_SOURCE_PATH for s in signatures)
    assert all(s.tags == () for s in signatures)

    # each declaration hashes differently
    assert len({s.content_hash for s in signatures}) == len(signatures)


@pytest.mark.unit
def test_builtin_version_falls_back_to_unknown(monkeypatch):
    monkeypatch.delenv("ACE_VERSION", raising=False)
    assert all(s.version == SIGNATURE_VERSION_UNKNOWN for s in load_builtin_signatures())


@pytest.mark.unit
def test_builtin_source_path_exists():
    assert os.path.isfile(os.path.join(get_base_dir(), BUILTIN_SOURCE_PATH))


#
# the dispatcher
#

@pytest.mark.unit
def test_load_signatures_dispatches(signature_repo):
    assert load_signatures(SignatureType.BUILTIN) == load_builtin_signatures()
    assert (load_signatures(SignatureType.YARA, _yara_dir(signature_repo))
            == load_yara_signatures(_yara_dir(signature_repo)))
    assert (load_signatures(SignatureType.HUNT, _hunt_dir(signature_repo))
            == load_hunt_signatures(_hunt_dir(signature_repo)))
    assert (load_signatures(SignatureType.OBSERVABLE_MODIFIER, _rules_file(signature_repo))
            == load_observable_modifier_signatures(_rules_file(signature_repo)))


@pytest.mark.unit
def test_load_signatures_rejects_a_path_for_builtins(signature_repo):
    with pytest.raises(ValueError):
        load_signatures(SignatureType.BUILTIN, signature_repo)


@pytest.mark.unit
@pytest.mark.parametrize("signature_type", [
    SignatureType.YARA,
    SignatureType.HUNT,
    SignatureType.OBSERVABLE_MODIFIER,
])
def test_load_signatures_requires_a_path(signature_type):
    with pytest.raises(ValueError):
        load_signatures(signature_type)


#
# provenance outside a git repo
#

@pytest.mark.unit
def test_loading_from_a_directory_that_is_not_a_repo(signature_dir):
    loaded = [
        load_yara_signatures(_yara_dir(signature_dir)),
        load_hunt_signatures(_hunt_dir(signature_dir)),
        load_observable_modifier_signatures(_rules_file(signature_dir)),
    ]

    for signatures in loaded:
        assert signatures
        assert all(s.version == SIGNATURE_VERSION_UNKNOWN for s in signatures)
        assert all(s.git_remote is None for s in signatures)


@pytest.mark.unit
@pytest.mark.parametrize("file_name,content", [
    ("yara/bv/broken.yar", "rule broken { this is not yara"),
    ("hunts/broken.yaml", "rule: [\n  unterminated"),
])
def test_unparseable_file_is_skipped(signature_repo, file_name, content):
    """One bad rule file does not hide the rest of the directory."""
    if file_name.startswith("yara"):
        loader, path = load_yara_signatures, _yara_dir(signature_repo)
    else:
        loader, path = load_hunt_signatures, _hunt_dir(signature_repo)

    baseline = loader(path)
    _write(os.path.join(signature_repo, file_name), content)

    assert loader(path) == baseline
