"""The marker rule (saq.svs.marker_rule, docs/SVS.md Part 3, *Where the SVS router looks*): a
`no_alert` YARA rule that finds the same markers MARKER_REGEX finds, written into the signature_dir
only when its content changed, so writing it never recompiles the scanner's rules for nothing."""

import logging
import os

import pytest
import yara

from saq.configuration.config import get_service_config
from saq.constants import SERVICE_YARA_SCANNER
from saq.svs.marker_rule import (
    MARKER_RULE,
    MARKER_RULE_DIR,
    MARKER_RULE_FILE,
    MARKER_RULE_NAME,
    install_marker_rule,
    marker_rule_path,
)
from saq.svs.markers import MARKER_REGEX, find_markers, find_markers_in_match

pytestmark = pytest.mark.unit

MARKER = "svs-abcdefghijklmnopqrstuvwxyz"


@pytest.fixture(scope="module")
def rules():
    return yara.compile(source=MARKER_RULE, error_on_warning=True)


def _rule_markers(rules, data: bytes) -> list[str]:
    """Every marker the rule's matches carry, read back the way attribution reads them."""
    result = []
    for match in rules.match(data=data):
        assert match.rule == MARKER_RULE_NAME
        for string in match.strings:
            for instance in string.instances:
                result.extend(find_markers_in_match(instance.matched_data))

    return list(dict.fromkeys(result))


def test_rule_is_no_alert(rules):
    (rule,) = list(rules)
    assert rule.identifier == MARKER_RULE_NAME
    assert rule.meta["modifiers"] == "no_alert"
    # rule tags are copied onto the file that matched
    assert rule.tags == []


@pytest.mark.parametrize("text", [
    MARKER,
    f" {MARKER} ",
    f"_{MARKER}",
    MARKER.upper(),
    f"cmd.exe /c \"whoami & REM {MARKER}\"\r\n",
    f"sh -c \"id; # {MARKER}\"\n",
    f"powershell.exe \"& {{whoami}}\" <# {MARKER} #>",
    f"-OutputFile C:\\Temp\\{MARKER}.txt",
    f"x{MARKER}",
    f"{MARKER}2",
    f"svs-{'a' * 25}",
    f"svs-{'a' * 27}",
    "no marker here",
])
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le"])
def test_rule_finds_what_the_regex_finds(rules, text, encoding):
    assert _rule_markers(rules, text.encode(encoding)) == find_markers(text)


def test_rule_finds_every_marker(rules):
    other = "svs-bbbbbbbbbbbbbbbbbbbbbbbbbb"
    assert _rule_markers(rules, f"{MARKER} then {other}".encode()) == [MARKER, other]


def test_find_markers_in_a_saved_match():
    # once its analysis is saved and loaded again a match is a str, NULs and all
    assert find_markers_in_match(f" {MARKER}\r".encode("utf-16-le").decode("latin-1")) == [MARKER]
    assert find_markers_in_match(f" {MARKER.upper()}\r".encode()) == [MARKER]


def test_install_writes_the_rule(tmp_path):
    assert install_marker_rule(str(tmp_path))

    path = tmp_path / MARKER_RULE_DIR / MARKER_RULE_FILE
    assert marker_rule_path(str(tmp_path)) == str(path)
    assert path.read_text() == MARKER_RULE
    assert sorted(os.listdir(path.parent)) == [MARKER_RULE_FILE]


def test_install_leaves_an_unchanged_rule_alone(tmp_path):
    """The scanner detects a rule change by mtime: rewriting the same bytes would recompile every
    rule each time a scanner starts."""
    install_marker_rule(str(tmp_path))
    path = marker_rule_path(str(tmp_path))
    os.utime(path, (1_000_000_000, 1_000_000_000))

    assert not install_marker_rule(str(tmp_path))
    assert os.path.getmtime(path) == 1_000_000_000


def test_install_replaces_a_changed_rule(tmp_path):
    path = tmp_path / MARKER_RULE_DIR / MARKER_RULE_FILE
    path.parent.mkdir()
    path.write_text("rule old { condition: false }\n")

    assert install_marker_rule(str(tmp_path))
    assert path.read_text() == MARKER_RULE


def test_install_failure_is_logged_not_raised(tmp_path, caplog):
    (tmp_path / MARKER_RULE_DIR).write_text("a file where the directory should be")

    with caplog.at_level(logging.ERROR):
        assert not install_marker_rule(str(tmp_path))

    assert "unable to write the svs marker rule" in caplog.text


def test_default_path_is_under_the_configured_signature_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "signature_dir", str(tmp_path))
    assert marker_rule_path() == str(tmp_path / MARKER_RULE_DIR / MARKER_RULE_FILE)


def test_marker_regex_is_what_the_rule_mirrors():
    # the rule's pattern is written by hand; if the marker format changes, both must change
    assert MARKER_REGEX.pattern == r"(?<![a-z0-9])svs-[a-z2-7]{26}(?![a-z0-9])"
    assert "svs-[a-z2-7]{26}" in MARKER_RULE
