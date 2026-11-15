"""The include boundary: a yara rule's ``include`` may reach only a regular file inside the
signature directory, through no symbolic link (saq.yara_scanning.include_guard)."""

import os

import pytest
import yara_scanner

from saq.yara_scanning.include_guard import guard_includes, is_allowed_read


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fp:
        fp.write(content)


# a valid rule that, were the include followed, would compile into the ruleset and be visible
LEAK = "rule include_escape_marker { condition: true }\n"


def _signature_dir(tmp_path):
    """A signature directory with two rule sets, and a `secret` rule file one directory above it
    that a well-behaved include must never reach."""
    sig = os.path.join(str(tmp_path), "signatures", "yara")
    _write(os.path.join(sig, "common", "shared.yar"), "rule shared_rule { condition: false }\n")
    _write(os.path.join(os.path.dirname(sig), "secret.yar"), LEAK)   # outside the signature dir
    return sig


def _rule_names(tmp_path, set_name, rule_text):
    """Load a signature directory holding one set with the given rule file, under the guard, and
    return the identifiers of every rule that compiled into the ruleset."""
    sig = _signature_dir(tmp_path)
    _write(os.path.join(sig, set_name, "rule.yar"), rule_text)
    scanner = yara_scanner.YaraScanner(signature_dir=sig, default_timeout=10)
    with guard_includes(sig):
        scanner.load_rules()
    return {rule.identifier for rule in (scanner.rules or [])}


@pytest.mark.unit
def test_include_within_signature_dir_still_works(tmp_path):
    # a sibling set of the same signature directory is reachable, as it was before the guard
    names = _rule_names(tmp_path, "acme", 'include "../common/shared.yar"\nrule uses_shared { condition: shared_rule }\n')
    assert "uses_shared" in names
    assert "shared_rule" in names


@pytest.mark.unit
@pytest.mark.parametrize("include_name", [
    "/{abs}/secret.yar",          # absolute path, filled in below
    "../secret.yar",              # climbs out of the signature directory
])
def test_include_outside_signature_dir_is_refused(tmp_path, include_name):
    sig = _signature_dir(tmp_path)
    include_name = include_name.format(abs=os.path.dirname(sig).strip("/")) if "{abs}" in include_name else include_name
    names = _rule_names(tmp_path, "acme", f'include "{include_name}"\nrule own_rule {{ condition: true }}\n')
    # the file's own rule still loads; the escaping include was compiled as empty, never read
    assert "own_rule" in names
    assert "include_escape_marker" not in names


@pytest.mark.unit
def test_symlink_include_is_refused(tmp_path):
    sig = _signature_dir(tmp_path)
    link = os.path.join(sig, "acme", "link.yar")
    os.makedirs(os.path.dirname(link), exist_ok=True)
    os.symlink(os.path.join(os.path.dirname(sig), "secret.yar"), link)   # a link out of the signature dir
    names = _rule_names(tmp_path, "acme", 'include "link.yar"\nrule own_rule { condition: true }\n')
    assert "own_rule" in names
    assert "include_escape_marker" not in names


@pytest.mark.unit
def test_symlinked_rule_file_is_refused(tmp_path):
    # a rule file that is itself a symbolic link is not read, so the link's target cannot be loaded
    sig = _signature_dir(tmp_path)
    acme = os.path.join(sig, "acme")
    os.makedirs(acme, exist_ok=True)
    os.symlink(os.path.join(os.path.dirname(sig), "secret.yar"), os.path.join(acme, "sneaky.yar"))
    scanner = yara_scanner.YaraScanner(signature_dir=sig, default_timeout=10)
    with guard_includes(sig):
        scanner.load_rules()
    assert "include_escape_marker" not in {rule.identifier for rule in (scanner.rules or [])}


@pytest.mark.unit
def test_is_allowed_read_boundary(tmp_path):
    sig = os.path.join(str(tmp_path), "signatures", "yara")
    _write(os.path.join(sig, "acme", "rule.yar"), "rule r { condition: true }\n")
    _write(os.path.join(os.path.dirname(sig), "secret.yar"), LEAK)

    assert is_allowed_read(os.path.join(sig, "acme", "rule.yar"), sig) is True
    assert is_allowed_read(os.path.join(os.path.dirname(sig), "secret.yar"), sig) is False   # ../
    assert is_allowed_read("/etc/passwd", sig) is False                                      # absolute
    assert is_allowed_read(os.path.join(sig, "acme"), sig) is False                          # a directory
    assert is_allowed_read(os.path.join(sig, "acme", "missing.yar"), sig) is False           # not there


@pytest.mark.unit
def test_guard_restores_open(tmp_path):
    sig = _signature_dir(tmp_path)
    assert "open" not in yara_scanner.__dict__
    with guard_includes(sig):
        assert "open" in yara_scanner.__dict__
    assert "open" not in yara_scanner.__dict__


@pytest.mark.unit
def test_refused_read_raises_permission_error(tmp_path):
    sig = _signature_dir(tmp_path)
    with guard_includes(sig):
        with pytest.raises(PermissionError):
            yara_scanner.open(os.path.join(os.path.dirname(sig), "secret.yar"))
        # a regular file inside the signature directory is still readable
        with yara_scanner.open(os.path.join(sig, "common", "shared.yar")) as fp:
            assert "shared_rule" in fp.read()
