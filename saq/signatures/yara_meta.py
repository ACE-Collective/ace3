"""How ACE reads the meta block of a YARA rule (docs/YARA_RULES.md).

One place for the interpretation, because two things read the same meta: the scanner module
(saq/modules/file_analysis/yara.py) acts on a match's meta, and the signature inventory
(saq/signatures/loaders/yara.py) reads it from rule source to answer "which rules are in QA mode".
If they parsed it differently, a rule could be listed as in QA mode while its matches alert, or the
other way round.

Meta values arrive as bool, int or str depending on how the author wrote them (`enabled = false`
vs `enabled = "false"`), from yara-python at match time and from plyara in the inventory.
"""

from collections.abc import Mapping
from typing import Any

from saq.signatures.model import Signature

META_ENABLED = "enabled"
META_MODIFIERS = "modifiers"

MODIFIER_QA = "qa"
MODIFIER_NO_ALERT = "no_alert"

FALSE_META_VALUES = {"false", "no", "0", "off", "disabled"}


def meta_enabled(meta: Mapping[str, Any] | None) -> bool:
    """Returns False only if the rule's `enabled` meta is set to a falsy value. Defaults to True."""
    meta = meta or {}
    if META_ENABLED not in meta:
        return True

    value = meta[META_ENABLED]
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() not in FALSE_META_VALUES


def meta_modifiers(meta: Mapping[str, Any] | None) -> list[str]:
    """The rule's `modifiers` meta as a list: comma separated, each entry stripped, empty entries
    dropped. An absent `modifiers` is an empty list."""
    value = (meta or {}).get(META_MODIFIERS)
    if value is None:
        return []

    return [modifier for modifier in (x.strip() for x in str(value).split(",")) if modifier]


def meta_is_qa(meta: Mapping[str, Any] | None) -> bool:
    """True when the rule runs in QA mode (`modifiers` includes `qa`)."""
    return MODIFIER_QA in meta_modifiers(meta)


def is_qa_signature(signature: Signature) -> bool:
    """True when an inventoried rule runs in QA mode. The inventory has already read its
    `modifiers` meta with meta_modifiers()."""
    return MODIFIER_QA in signature.modifiers
