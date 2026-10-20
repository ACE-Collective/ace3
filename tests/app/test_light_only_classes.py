"""Bootstrap 5.3 fixes these classes to light colors in every color mode. They reach the page from
integration templates and from class names built in config and Python, where no template check
sees them, so saq.css maps each one to a theme-aware equivalent for dark mode instead."""

import pathlib
import re

import pytest

SAQ_CSS = pathlib.Path(__file__).resolve().parents[2] / "app" / "static" / "css" / "saq.css"

LIGHT_ONLY = [
    "bg-white",
    "bg-light",
    "text-bg-light",
    "text-dark",
    "border-dark",
    "border-black",
    "btn-outline-dark",
    "table-primary",
    "table-secondary",
    "table-success",
    "table-info",
    "table-warning",
    "table-danger",
    "table-light",
]


@pytest.mark.unit
def test_light_only_bootstrap_classes_have_dark_overrides():
    css = SAQ_CSS.read_text()
    missing = [
        name for name in LIGHT_ONLY
        if not re.search(r"\[data-bs-theme=dark\] \." + re.escape(name) + r"(?![\w-])", css)
    ]
    assert missing == []
