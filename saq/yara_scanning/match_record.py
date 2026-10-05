"""A YARA match record: the dict yara_scanner returns for one rule that matched one file (rule,
namespace, commit, meta, tags, strings), as stores keep it. Shared by every store of matches: YARA
QA (saq/yara_qa/store.py) and SVS samples (saq/svs/capture.py)."""

import json
from typing import Any, Optional

from saq.json_encoding import _JSONEncoder


def serialize_match_record(match_result: dict) -> bytes:
    """The full match record as it is stored: JSON, never truncated. A string's bytes are
    decoded the way an alert's JSON decodes them (saq.json_encoding._JSONEncoder), which is lossy;
    the scanner protocol's own encoding (protocol.py) is the byte-exact one."""
    return json.dumps(match_result, cls=_JSONEncoder).encode("utf-8")


def _string_entry(entry: Any) -> Optional[tuple[str, int, Optional[int]]]:
    """(identifier, instance count, first offset) of one entry of a match's strings list, which is
    a (offset, identifier, data) tuple from yara_scanner (a list once saved as JSON), or a
    yara.StringMatch from newer yara-python."""
    if isinstance(entry, (tuple, list)) and len(entry) >= 2:
        return str(entry[1]), 1, entry[0] if isinstance(entry[0], int) else None

    identifier = getattr(entry, "identifier", None)
    if identifier is None:
        return None

    instances = list(getattr(entry, "instances", None) or [])
    first_offset = getattr(instances[0], "offset", None) if instances else None
    return str(identifier), len(instances), first_offset


def summarize_match_record(match_result: dict) -> dict:
    """What a list shows about a match without loading the record: the rule, its meta and tags,
    and for each string identifier how many times it matched and where it first matched. Its size
    depends on the rule, not on the file, so it needs no limit. Accepts the strings as yara_scanner
    returns them, as yara-python's StringMatch objects, and as lists once a record was saved as
    JSON."""
    strings: dict[str, dict] = {}
    total = 0
    for entry in match_result.get("strings") or []:
        parsed = _string_entry(entry)
        if parsed is None:
            continue

        identifier, count, offset = parsed
        total += count
        summary = strings.setdefault(identifier, {"identifier": identifier, "count": 0, "first_offset": None})
        summary["count"] += count
        if offset is not None and (summary["first_offset"] is None or offset < summary["first_offset"]):
            summary["first_offset"] = offset

    return {
        "rule": match_result.get("rule"),
        "namespace": match_result.get("namespace"),
        "commit": match_result.get("commit"),
        "tags": list(match_result.get("tags") or []),
        "meta": match_result.get("meta") or {},
        "string_match_count": total,
        "strings": sorted(strings.values(), key=lambda s: s["identifier"]),
    }
