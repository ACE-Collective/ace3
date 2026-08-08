"""Reads yara rules as signatures

The traversal mirrors YaraScanner.__init__: a signature_dir holds one
subdirectory per set of rules, and each of those is read for the .yar/.yara
files sitting directly inside it. Files loose in the signature_dir and files
nested deeper than one level are not loaded, because the scanner does not load
them either.

This is an inventory reader, not a validator: rules are parsed from source with
plyara and never compiled. a single .yar file usually holds several rules, each
of which is its own signature with its own content hash.

Versions follow the same declaration the scanner uses: a rule directory named in
git_repo_dirs is versioned by the commit of the repo it belongs to, and every
other directory is versioned SIGNATURE_VERSION_UNKNOWN - which is exactly what a
detection on its rules would record. Omitting git_repo_dirs falls back to
resolving an enclosing repo for every rule directory, which is more informative
but can report a version the detection path would not.
"""


import logging
import os
from dataclasses import replace

import plyara

from saq.signatures.builtin import SIGNATURE_VERSION_UNKNOWN
from saq.signatures.git_context import GitContext
from saq.signatures.loaders.util import content_hash, normalize_tags, sort_signatures
from saq.signatures.model import Signature, SignatureType

YARA_FILE_EXTENSIONS = (".yar", ".yara")

# rule files ACE generates into the signature_dir from observable detections
# (saq/observables/export/yara.py) - exported observables, not authored signatures
GENERATED_RULE_DIR_NAMES = {"observable_export"}

# meta key holding the comma separated ATT&CK techniques a rule detects
MITRE_ATTACK_META = "mitre_attack"

# prefix applied to mitre_attack techniques so they match the tag convention
# hunts already use (mitre:T1518.001)
MITRE_TAG_PREFIX = "mitre:"


def _flatten_metadata(parsed_rule: dict) -> dict[str, str]:
    """plyara returns rule metadata as a list of single key dicts (a rule can
    repeat a key). collapses it into a dict, last value winning."""
    result = {}
    for entry in parsed_rule.get("metadata") or []:
        if isinstance(entry, dict):
            for key, value in entry.items():
                result[key] = value

    return result


def _rule_tags(parsed_rule: dict, metadata: dict[str, str]) -> tuple[str, ...]:
    """Returns the rule's native yara tags (rule x: phone ioc smishing) plus its
    mitre_attack techniques as mitre: prefixed tags."""
    tags = list(parsed_rule.get("tags") or [])

    mitre_attack = metadata.get(MITRE_ATTACK_META)
    if mitre_attack:
        for technique in str(mitre_attack).split(","):
            technique = technique.strip()
            if technique:
                tags.append(f"{MITRE_TAG_PREFIX}{technique}")

    return normalize_tags(tags)


def _rule_source(source_lines: list[str], parsed_rule: dict) -> str | None:
    """Returns the verbatim source of a single rule, sliced out of the file it
    was parsed from using the line range plyara recorded for it."""
    start_line = parsed_rule.get("start_line")
    stop_line = parsed_rule.get("stop_line")
    if not start_line or not stop_line:
        return None

    return "".join(source_lines[start_line - 1:stop_line])


def _parse_rule_file(path: str, git_context: GitContext) -> list[Signature]:
    """Returns every trackable rule in one .yar file."""
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as fp:
        source = fp.read()

    # plyara accumulates parsed rules across calls, so it needs to be a new
    # instance per file (see saq.submission_filter for the same pattern)
    parsed_rules = plyara.Plyara().parse_string(source)
    source_lines = source.splitlines(keepends=True)
    source_path = git_context.relative_path(path)

    result = []
    for parsed_rule in parsed_rules:
        name = parsed_rule.get("rule_name") or "unnamed"
        metadata = _flatten_metadata(parsed_rule)

        rule_uuid = metadata.get("uuid")
        if not rule_uuid:
            logging.warning("yara rule %s in %s has no uuid meta - not tracking it", name, source_path)
            continue

        rule_source = _rule_source(source_lines, parsed_rule)
        if rule_source is None:
            logging.warning("yara rule %s in %s has no source line range - not tracking it", name, source_path)
            continue

        result.append(Signature(
            name=name,
            uuid=str(rule_uuid).strip(),
            type=SignatureType.YARA,
            version=git_context.version,
            git_remote=git_context.git_remote,
            source_path=source_path,
            content_hash=content_hash(rule_source),
            tags=_rule_tags(parsed_rule, metadata),
        ))

    return result


def _declared_repo_paths(signature_dir: str, git_repo_dirs: list[str]) -> set[str]:
    """Resolves git_repo_dirs entries - a subdirectory name, a relative path or an
    absolute one - the same way YaraScanner._resolve_signature_subdir does."""
    return {
        os.path.realpath(entry if os.path.isabs(entry) else os.path.join(signature_dir, entry))
        for entry in git_repo_dirs
    }


def load_yara_signatures(signature_dir: str, git_repo_dirs: list[str] | None = None) -> list[Signature]:
    """Loads every yara signature under signature_dir, which is the directory
    ACE configures as service_yara.signature_dir: one subdirectory per set of
    rules, each holding .yar/.yara files.

    git_repo_dirs is the matching service_yara.git_repo_dirs: only the rule
    directories it names are versioned by their repo's commit, so the inventory
    reports the same version a detection on those rules would. Omit it to resolve
    an enclosing repo for every rule directory instead - the layout exists so that
    independently cloned rule repos can sit side by side."""
    if not os.path.isdir(signature_dir):
        raise NotADirectoryError(f"yara signature_dir {signature_dir} is not a directory")

    declared_repo_paths = None
    if git_repo_dirs is not None:
        declared_repo_paths = _declared_repo_paths(signature_dir, git_repo_dirs)

    result: list[Signature] = []
    for entry in sorted(os.listdir(signature_dir)):
        rule_dir = os.path.join(signature_dir, entry)
        if not os.path.isdir(rule_dir):
            # the scanner only loads rules out of the subdirectories, so a .yar
            # sitting loose in the signature_dir is not a signature
            continue

        if entry in GENERATED_RULE_DIR_NAMES:
            logging.debug("skipping generated rule directory %s", rule_dir)
            continue

        git_context = GitContext.resolve(rule_dir)
        if declared_repo_paths is not None and os.path.realpath(rule_dir) not in declared_repo_paths:
            # not declared a git repo, so the scanner reports no commit for its
            # matches. the root is kept so source_path stays repo relative.
            git_context = replace(git_context, git_remote=None, version=SIGNATURE_VERSION_UNKNOWN)

        for file_name in sorted(os.listdir(rule_dir)):
            if not file_name.lower().endswith(YARA_FILE_EXTENSIONS):
                continue

            rule_file = os.path.join(rule_dir, file_name)
            if not os.path.isfile(rule_file):
                continue

            try:
                result.extend(_parse_rule_file(rule_file, git_context))
            except Exception as e:
                logging.warning("unable to load yara signatures from %s: %s", rule_file, e)

    return sort_signatures(result)
