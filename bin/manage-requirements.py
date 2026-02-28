#!/usr/bin/env python3
"""
Manage pinned Python requirements.

Usage:
    manage-requirements.py [requirements_file]        # print pinned versions to stdout
    manage-requirements.py --update                   # write pinned versions to installer/requirements-pinned.txt
    manage-requirements.py --check                    # compare pinned file against installed versions
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

from packaging.version import Version

PINNED_FILE = Path("installer/requirements-pinned.txt")


def get_installed_versions():
    """Return a dict of package_name_lower -> (canonical_name, version) from pip freeze."""
    result = subprocess.run(
        ["pip", "freeze"],
        capture_output=True,
        text=True,
        check=True,
    )
    versions = {}
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Match package==version (extras in package name possible, e.g. package[extra]==version)
        m = re.match(r"^([a-zA-Z0-9_-]+)(\[[^\]]*\])?\s*==\s*(.+)$", line)
        if m:
            base_name = m.group(1)
            extras = m.group(2) or ""
            version = m.group(3)
            versions[base_name.lower()] = (base_name + extras, version)
    return versions


def parse_requirement_line(line):
    """
    Parse a requirement line. Returns (package_base, extras_part) or None if not a package line.

    Handles: package, package[extra], package>=x, package==x, package[extra]>=x, etc.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # Skip editable installs, recursive requirements, etc.
    if line.startswith("-") or line.startswith("http") or line.startswith("git+"):
        return None
    # Extract package name (base + optional extras)
    m = re.match(r"^([a-zA-Z0-9_-]+)(\[[^\]]*\])?", line)
    if not m:
        return None
    base = m.group(1)
    extras = m.group(2) or ""
    return (base, extras)


def generate_pinned_lines(lines, installed):
    """Generate pinned output lines from requirement lines and installed versions."""
    output = []
    for line in lines:
        parsed = parse_requirement_line(line)
        if parsed is None:
            # Keep comments, blanks, and unsupported lines as-is
            output.append(line)
            continue
        base, extras = parsed
        key = base.lower()
        if key not in installed:
            # Package not installed; keep original line
            output.append(line)
            continue
        _, version = installed[key]
        # preserve original package name and extras from input
        pkg_display = base + extras
        output.append("%s==%s" % (pkg_display, version))
    return output


def do_update(requirements_file):
    """Pin requirements and write to the pinned file."""
    installed = get_installed_versions()
    lines = requirements_file.read_text().splitlines()
    pinned_lines = generate_pinned_lines(lines, installed)
    PINNED_FILE.write_text("\n".join(pinned_lines) + "\n")
    print("wrote pinned requirements to %s" % PINNED_FILE, file=sys.stderr)


def do_check():
    """Compare pinned file against installed versions and report outdated packages."""
    if not PINNED_FILE.exists():
        print("error: pinned file not found: %s" % PINNED_FILE, file=sys.stderr)
        sys.exit(1)

    installed = get_installed_versions()
    lines = PINNED_FILE.read_text().splitlines()
    outdated = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([a-zA-Z0-9_-]+)(\[[^\]]*\])?\s*==\s*(.+)$", line)
        if not m:
            continue
        base = m.group(1)
        pinned_version = m.group(3)
        key = base.lower()
        if key not in installed:
            continue
        _, installed_version = installed[key]
        if Version(installed_version) > Version(pinned_version):
            outdated.append((base, pinned_version, installed_version))

    if outdated:
        for name, pinned, current in outdated:
            print("%s: pinned %s, installed %s" % (name, pinned, current))
        sys.exit(1)

    sys.exit(0)


def do_print(requirements_file):
    """Print pinned versions to stdout (default behavior)."""
    installed = get_installed_versions()
    lines = requirements_file.read_text().splitlines()
    pinned_lines = generate_pinned_lines(lines, installed)
    for line in pinned_lines:
        print(line)


def main():
    parser = argparse.ArgumentParser(
        description="manage pinned Python requirements"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--update",
        action="store_true",
        help="write pinned versions to %s" % PINNED_FILE,
    )
    group.add_argument(
        "--check",
        action="store_true",
        help="compare pinned file against installed versions",
    )
    parser.add_argument(
        "requirements_file",
        nargs="?",
        default="installer/requirements.txt",
        help="path to requirements file (default: installer/requirements.txt)",
    )
    args = parser.parse_args()

    requirements_file = Path(args.requirements_file)

    if args.check:
        do_check()
    elif args.update:
        if not requirements_file.exists():
            print("error: file not found: %s" % requirements_file, file=sys.stderr)
            sys.exit(1)
        do_update(requirements_file)
    else:
        if not requirements_file.exists():
            print("error: file not found: %s" % requirements_file, file=sys.stderr)
            sys.exit(1)
        do_print(requirements_file)


if __name__ == "__main__":
    main()
