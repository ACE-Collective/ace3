"""Guards against the pre-UUID filter API creeping back into the tree.

These are cheap greps rather than behavioural tests: the call sites they cover are spread
across templates and JS where a stale one fails silently in the browser rather than in a
test run.
"""

import ast
import pathlib
import re

import pytest

APP = pathlib.Path(__file__).resolve().parents[2] / "app"


def _files(root, suffix):
    return [p for p in root.rglob(f"*{suffix}") if "__pycache__" not in str(p)]


@pytest.mark.unit
def test_no_template_calls_the_removed_set_filters_helper():
    """set_filters() overwrote the analyst's filter set outright. It was replaced by
    apply_temp_filter(), which is revertible. One call site (alert.html:490) had also been
    passing the wrong shape entirely -- a dict where a list of entries was expected."""
    offenders = [
        str(p) for p in _files(APP / "templates", ".html")
        if re.search(r"(?<![a-z_])set_filters\(", p.read_text())
    ]
    assert offenders == []


@pytest.mark.unit
def test_no_template_calls_the_removed_add_filter_route():
    """analysis.add_filter is gone; url_for() on it raises BuildError at render time."""
    offenders = [
        str(p) for p in _files(APP / "templates", ".html")
        if "analysis.add_filter" in p.read_text()
    ]
    assert offenders == []


@pytest.mark.unit
def test_no_python_reads_filter_contents_out_of_the_session():
    """Filter contents live in the database; the session carries UUIDs only. A stray
    session["filters"] read would silently see nothing rather than fail loudly.

    Parsed rather than grepped so that prose mentioning the old key -- the legacy-cookie
    migration has to describe what it is migrating -- does not trip the guard."""
    offenders = []
    for path in _files(APP, ".py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Subscript)
                    and isinstance(node.value, ast.Name) and node.value.id == "session"
                    and isinstance(node.slice, ast.Constant) and node.slice.value == "filters"):
                offenders.append(f"{path}:{node.lineno}")

    assert offenders == []


#
# WYSIWYG saves: the browser half of the contract in
# app/analysis/views/edit/filters.py::_posted_filters_or_effective
#

@pytest.mark.unit
def test_every_save_modal_trigger_declares_its_filter_source():
    """#save_filter_modal is shared by "Save as..." (saves the editor's rows) and by the
    temp banner's "Save a copy" (saves what is in effect). A trigger that declares neither
    silently inherits whichever payload the last one left behind -- which is exactly the
    class of bug this guard exists for. The next entry point must state its source."""
    offenders = []
    for path in _files(APP / "templates", ".html"):
        for line in path.read_text().splitlines():
            if 'data-bs-target="#save_filter_modal"' in line and "prepare_save(" not in line:
                offenders.append(f"{path}: {line.strip()}")

    assert offenders == []


@pytest.mark.unit
def test_both_save_paths_send_the_on_screen_filter():
    """Save and Save as must post what the editor shows. Without this, reverting the JS
    half leaves the Python half reading a field nobody sends -- and the route falls back to
    the session, which is the original bug, silently restored."""
    js = (APP / "static" / "js" / "manage_alerts.js").read_text()

    assert re.search(r"function save_current_filter\b[\s\S]*?compute_filter_settings\(", js), \
        "save_current_filter() must serialize the editor"
    assert re.search(r"function prepare_save\b[\s\S]*?compute_filter_settings\(", js), \
        "prepare_save('editor') must snapshot the editor before the modal handoff"
    assert re.search(r"function save_filter_as\b[\s\S]*?append\('filters'", js), \
        "save_filter_as() must post the snapshotted filter list"
