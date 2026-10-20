"""Run markers (saq.svs.markers, docs/SVS.md Part 3, *Markers*)."""

import pytest

from saq.svs.markers import MARKER_LENGTH, MARKER_REGEX, find_markers, new_marker, normalize_marker

pytestmark = pytest.mark.unit


def test_new_marker_format():
    marker = new_marker()
    assert marker.startswith("svs-") and len(marker) == MARKER_LENGTH == 30
    assert marker == marker.lower()
    assert MARKER_REGEX.fullmatch(marker)


def test_markers_are_random():
    assert len({new_marker() for _ in range(1000)}) == 1000


def test_find_markers():
    marker = new_marker()
    text = f"powershell.exe \"& {{whoami}}\" <# {marker.upper()} #> & REM {marker}; other svs-{'a' * 25}"
    assert find_markers(text) == [marker]
    assert find_markers(f"x{marker}") == []
    assert find_markers(f"{marker}a") == []
    assert find_markers(None) == []


def test_normalize_marker():
    assert normalize_marker(" SVS-ABC ") == "svs-abc"
