"""Bootstrap 5.3 fixes these classes to light-mode colors in every color mode. They reach the page
from integration templates and from class names built in config and Python, where no template check
sees them, so saq.css maps each one onto the dark palette instead."""

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
    # light-mode theme colors with white text
    "btn-primary",
    "btn-secondary",
    "btn-success",
    "btn-warning",
    "btn-danger",
    "btn-outline-primary",
    "btn-outline-secondary",
    "btn-outline-success",
    "btn-outline-warning",
    "btn-outline-danger",
    "text-bg-primary",
    "text-bg-secondary",
    "text-bg-success",
    "text-bg-danger",
    "nav-pills",
    "pagination",
    "list-group",
    "dropdown-menu",
]


@pytest.mark.unit
def test_light_only_bootstrap_classes_have_dark_overrides():
    css = SAQ_CSS.read_text()
    # the class anywhere in a selector that starts in dark mode, e.g. inside :is(...)
    missing = [
        name for name in LIGHT_ONLY
        if not re.search(r"\[data-bs-theme=dark\] [^{]*\." + re.escape(name) + r"(?![\w-])", css)
    ]
    assert missing == []
