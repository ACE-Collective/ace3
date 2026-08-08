"""Reads observable modifier rules as signatures

The whole ruleset is a single yaml file - the one ACE configures as
analysis_module_observable_modifier.rules_config_path - so there is nothing to
traverse.

Only rules that add detection points are signatures. Nothing structural marks
such a rule: it is an ordinary rule whose actions include add_detection_points
(see RuleActions.apply in saq/modules/util/observable_modifier.py), so that is
what we filter on.

Rules live many-to-a-file, so the content hash is taken over the individual
rule's yaml block rather than the file."""

import logging
import os

import yaml

from saq.signatures.git_context import GitContext
from saq.signatures.loaders.util import content_hash, normalize_tags, sort_signatures
from saq.signatures.model import Signature, SignatureType

RULES_KEY = "rules"


def _raw_rule_blocks(source: str) -> list[str]:
    """Returns the verbatim yaml source of each entry of the top level rules
    list, in document order. Returns an empty list if the marks can't be
    resolved."""
    node = yaml.compose(source)
    if node is None:
        return []

    for key_node, value_node in getattr(node, "value", []):
        if getattr(key_node, "value", None) != RULES_KEY:
            continue

        return [
            source[item.start_mark.index:item.end_mark.index].rstrip()
            for item in value_node.value
        ]

    return []


def load_observable_modifier_signatures(rules_config_path: str) -> list[Signature]:
    """Loads every detection-point-adding rule from the observable modifier
    ruleset at rules_config_path."""
    if not os.path.isfile(rules_config_path):
        raise FileNotFoundError(f"observable modifier rules file {rules_config_path} does not exist")

    git_context = GitContext.resolve(rules_config_path)
    source_path = git_context.relative_path(rules_config_path)

    with open(rules_config_path, "r", encoding="utf-8", errors="surrogateescape") as fp:
        source = fp.read()

    data = yaml.safe_load(source)
    rules = data.get(RULES_KEY) if isinstance(data, dict) else None
    if not isinstance(rules, list):
        logging.warning("observable modifier rules file %s has no rules list", source_path)
        return []

    # both come from the same document, so they line up by index
    raw_blocks = _raw_rule_blocks(source)
    if len(raw_blocks) != len(rules):
        logging.warning(
            "could not resolve the source of every rule in %s (%d blocks for %d rules) - not tracking it",
            source_path, len(raw_blocks), len(rules))
        return []

    result = []
    for rule, raw_block in zip(rules, raw_blocks):
        if not isinstance(rule, dict):
            continue

        actions = rule.get("actions") or {}
        if not isinstance(actions, dict):
            continue

        # only rules that add detection points are signatures
        if not actions.get("add_detection_points"):
            continue

        name = rule.get("name") or "unnamed"
        rule_uuid = rule.get("uuid")
        if not rule_uuid:
            logging.warning(
                "observable modifier rule %s in %s has no uuid - not tracking it", name, source_path)
            continue

        result.append(Signature(
            name=str(name),
            uuid=str(rule_uuid).strip(),
            type=SignatureType.OBSERVABLE_MODIFIER,
            version=git_context.version,
            git_remote=git_context.git_remote,
            source_path=source_path,
            content_hash=content_hash(raw_block),
            tags=normalize_tags(actions.get("add_tags")),
        ))

    return sort_signatures(result)
