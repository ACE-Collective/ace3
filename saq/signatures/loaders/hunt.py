"""Reads hunts as signatures

The traversal mirrors HuntManager._list_hunt_yaml: one non-recursive scan of a
rule directory for .yaml files, skipping template.yaml and *.include.yaml. one
file is one hunt. Subdirectories are not scanned, which is what keeps the
includes/ directories repos keep alongside their hunts out of the inventory.

The include merging is delegated to the same pure function the hunter itself
uses (saq.collectors.hunter.loader.load_merged_yaml) so a hunt whose name, uuid
or tags come from an include is read correctly, but the result is read as a
plain dict rather than validated against a HuntConfig subclass - that would
require knowing the hunt type's Pydantic model and a running HuntManager."""

import logging
import os

from saq.collectors.hunter.loader import load_merged_yaml
from saq.signatures.git_context import GitContext
from saq.signatures.loaders.util import content_hash, normalize_tags, sort_signatures
from saq.signatures.model import Signature, SignatureType

# the same two exclusions HuntManager._list_hunt_yaml applies: neither of these
# is a hunt, they are the starting point for one and shared fragments
HUNT_TEMPLATE_FILE_NAME = "template.yaml"
HUNT_INCLUDE_FILE_SUFFIX = ".include.yaml"


def _is_hunt_file(file_name: str) -> bool:
    if not file_name.endswith(".yaml"):
        return False

    return file_name != HUNT_TEMPLATE_FILE_NAME and not file_name.endswith(HUNT_INCLUDE_FILE_SUFFIX)


def _parse_hunt_file(path: str, git_context: GitContext) -> list[Signature]:
    """Returns the hunt in one yaml file, or nothing if it isn't trackable."""
    source_path = git_context.relative_path(path)

    merged, _ = load_merged_yaml(path)
    rule = merged.get("rule") if isinstance(merged, dict) else None
    if not isinstance(rule, dict):
        logging.warning("hunt yaml %s has no top level rule mapping - not tracking it", source_path)
        return []

    hunt_uuid = rule.get("uuid")
    if not hunt_uuid:
        logging.warning("hunt %s has no uuid - not tracking it", source_path)
        return []

    # the raw file is the signature content. the merged dict is deliberately
    # not hashed: load_merged_yaml rewrites relative file paths to absolute
    # ones, which would make the hash depend on where the repo is checked out.
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as fp:
        source = fp.read()

    return [Signature(
        name=str(rule.get("name") or "unnamed"),
        uuid=str(hunt_uuid).strip(),
        type=SignatureType.HUNT,
        version=git_context.version,
        git_remote=git_context.git_remote,
        source_path=source_path,
        content_hash=content_hash(source),
        tags=normalize_tags(rule.get("tags")),
    )]


def load_hunt_signatures(rule_dir: str) -> list[Signature]:
    """Loads every hunt in rule_dir, which is one of the directories ACE
    configures as hunt_type_<type>.rule_dirs. A hunt type with several rule
    directories is several calls."""
    if not os.path.isdir(rule_dir):
        raise NotADirectoryError(f"hunt rule_dir {rule_dir} is not a directory")

    git_context = GitContext.resolve(rule_dir)

    result: list[Signature] = []
    for entry in sorted(os.scandir(rule_dir), key=lambda e: e.name):
        if not entry.is_file() or not _is_hunt_file(entry.name):
            continue

        try:
            result.extend(_parse_hunt_file(entry.path, git_context))
        except Exception as e:
            logging.warning("unable to load hunt signature from %s: %s", entry.path, e)

    return sort_signatures(result)
