import json
from types import SimpleNamespace

import pytest

from saq.yara_scanning.match_record import serialize_match_record, summarize_match_record


def _match(strings) -> dict:
    return {"rule": "r", "namespace": "n", "commit": None, "tags": ["t"], "meta": {"uuid": "u"}, "strings": strings}


@pytest.mark.unit
def test_summary_of_string_match_objects():
    """Newer yara-python returns StringMatch objects with instances instead of tuples."""
    summary = summarize_match_record(_match([
        SimpleNamespace(identifier="$a", instances=[SimpleNamespace(offset=40), SimpleNamespace(offset=90)]),
        SimpleNamespace(identifier="$b", instances=[]),
    ]))

    assert summary["string_match_count"] == 2
    assert summary["strings"] == [
        {"identifier": "$a", "count": 2, "first_offset": 40},
        {"identifier": "$b", "count": 0, "first_offset": None},
    ]


@pytest.mark.unit
def test_summary_of_tuples_and_of_a_saved_record():
    """yara_scanner returns (offset, identifier, bytes) tuples; a record saved as JSON has lists."""
    tuples = _match([(50, "$a", b"x"), (10, "$a", b"x"), (5, "$b", b"y")])
    saved = json.loads(serialize_match_record(tuples))

    for record in (tuples, saved):
        summary = summarize_match_record(record)
        assert summary["rule"] == "r"
        assert summary["meta"] == {"uuid": "u"}
        assert summary["tags"] == ["t"]
        assert summary["string_match_count"] == 3
        assert summary["strings"] == [
            {"identifier": "$a", "count": 2, "first_offset": 10},
            {"identifier": "$b", "count": 1, "first_offset": 5},
        ]
