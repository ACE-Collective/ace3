"""Keeps the GUI readable in dark mode: these Bootstrap classes are fixed to light colors and
do not follow data-bs-theme. Each has a theme-aware replacement (docs/USER_PREFERENCES.md)."""

import pathlib
import re

import pytest

APP = pathlib.Path(__file__).resolve().parents[2] / "app"

# class -> what to use instead
LIGHT_ONLY = {
    "bg-light": "bg-body-tertiary",
    "bg-white": "bg-body",
    "text-dark": "text-body-emphasis",
    "text-bg-light": "bg-body-secondary text-body-emphasis",
    "border-dark": "border-strong",
    "border-black": "border-strong",
    "table-light": "nothing (table cells already take the body background)",
}

PATTERN = re.compile(r"(?<![\w-])(" + "|".join(map(re.escape, LIGHT_ONLY)) + r")(?![\w-])")


def _gui_sources():
    yield from (APP / "templates").rglob("*.html")
    yield from (p for p in (APP / "static" / "js").rglob("*.js") if not p.name.endswith(".min.js"))


@pytest.mark.unit
def test_no_light_only_bootstrap_classes():
    offenders = [
        f"{path.relative_to(APP)}:{number}: {match.group(1)} -> use {LIGHT_ONLY[match.group(1)]}"
        for path in _gui_sources()
        for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1)
        for match in PATTERN.finditer(line)
    ]
    assert offenders == []
