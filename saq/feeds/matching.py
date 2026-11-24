"""Running a definition's YARA rule over an entry (docs/FEED_WATCHES.md, *Matching*).

service_feed_watch compiles the rules itself with yara-python: they never go into the yara service's
ruleset, where they would run against every file ACE scans. Each field (title, summary, content,
categories) is scanned on its own with the external variable `field` set to its name, so a rule can
require a string in the title. The excerpt is the first matched string with some text either side.
"""

from dataclasses import dataclass, field as dataclass_field
from typing import Optional

import yara

from saq.feeds.entries import ENTRY_FIELDS

# characters of context kept either side of the matched string
EXCERPT_CONTEXT = 120

# a rule that takes longer than this on one field stops
SCAN_TIMEOUT_SECONDS = 10


class RuleError(ValueError):
    """The rule does not compile; the message is yara's."""


@dataclass
class RuleMatch:
    matched: bool
    field: Optional[str] = None
    excerpt: Optional[str] = None
    rules: list[str] = dataclass_field(default_factory=list)


def compile_rule(source: str) -> yara.Rules:
    try:
        return yara.compile(source=source, externals={"field": ""})
    except yara.Error as e:
        raise RuleError(str(e)) from None


def _excerpt(text: str, data: bytes, offset: int, length: int) -> str:
    # offsets are into the utf-8 bytes; map them back to characters of the field
    start = len(data[:offset].decode("utf-8", "ignore"))
    end = start + len(data[offset:offset + length].decode("utf-8", "ignore"))
    return text[max(0, start - EXCERPT_CONTEXT):end + EXCERPT_CONTEXT].strip()


def scan_entry(rules: yara.Rules, fields: dict[str, str]) -> RuleMatch:
    """The rule's answer for an entry: matched when it matched any field. Raises yara.Error for a scan
    that failed (a timeout)."""
    result = RuleMatch(matched=False)
    for name in ENTRY_FIELDS:
        text = fields.get(name) or ""
        if not text:
            continue

        data = text.encode("utf-8")
        matches = rules.match(data=data, externals={"field": name}, timeout=SCAN_TIMEOUT_SECONDS)
        if not matches:
            continue

        result.matched = True
        result.rules.extend(match.rule for match in matches if match.rule not in result.rules)
        if result.excerpt is None:
            result.field = name
            for match in matches:
                for string in match.strings:
                    if string.instances:
                        instance = string.instances[0]
                        result.excerpt = _excerpt(text, data, instance.offset, instance.matched_length)
                        break
                if result.excerpt is not None:
                    break
            if result.excerpt is None:
                # a condition without strings (field == "title" and filesize > 0): the field itself
                result.excerpt = text[:2 * EXCERPT_CONTEXT]

    return result
