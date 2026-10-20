"""The SVS area's tabs (docs/SVS.md, Part 5, *One SVS area*), and what the navigation bar needs
from the area on every page."""

from functools import cache
from urllib.parse import urlencode

from flask import current_app
from flask_login import current_user

from aceapi_v2.saved_filters.service import (
    DEFAULT_SVS_COVERAGE_SAVED_FILTERS,
    DEFAULT_SVS_RUN_SAVED_FILTERS,
    DEFAULT_SVS_TEST_SAVED_FILTERS,
    DEFAULT_SVS_WORKLIST_SAVED_FILTERS,
)
from app.blueprints import svs
from saq.gui.filter_screens import SVS_COVERAGE_SCREEN, SVS_RUNS_SCREEN, SVS_TESTS_SCREEN, SVS_WORKLIST_SCREEN
from saq.gui.filter_url import encode_filter_query
from saq.permissions.logic import user_has_permission

# The area's tabs, in order. A tab shows only when its endpoint is registered and the user holds its
# permission; `active` names the endpoints it is the open tab on.
SVS_TABS = [
    {
        "endpoint": "svs.runs",
        "title": "Runs",
        "active": ("svs.runs", "svs.batches", "svs.run_detail"),
        "major": "svs",
        "minor": "run_read",
    },
    {
        "endpoint": "svs.tests",
        "title": "Tests",
        "active": ("svs.tests", "svs.test_detail"),
        "major": "svs",
        "minor": "run_read",
    },
    {
        "endpoint": "svs.coverage",
        "title": "Coverage",
        "active": ("svs.coverage", "svs.coverage_detail"),
        "major": "svs",
        "minor": "run_read",
    },
    {
        "endpoint": "svs.worklist",
        "title": "Worklist",
        "active": ("svs.worklist", "svs.worklist_signature"),
        "major": "svs",
        "minor": "run_read",
    },
    {
        "endpoint": "svs.test_hosts",
        "title": "Test hosts",
        "active": ("svs.test_hosts",),
        "major": "svs",
        "minor": "admin",
    },
]


@svs.context_processor
def svs_tab_context() -> dict:
    tabs = [tab for tab in SVS_TABS
            if tab["endpoint"] in current_app.view_functions
            and user_has_permission(current_user.id, tab["major"], tab["minor"])]
    return {"svs_tabs": tabs}


@svs.app_template_global()
@cache
def svs_needs_attention_f() -> list[str]:
    """The f= values of the runs screen's Needs attention view: what the SVS entry of the
    navigation bar counts, and the view the Runs tab opens with."""
    return encode_filter_query(list(DEFAULT_SVS_RUN_SAVED_FILTERS[0]["filters"]), screen=SVS_RUNS_SCREEN)


@svs.app_template_global()
@cache
def svs_tests_default_f() -> list[str]:
    """The f= values of the tests screen's default view, the tests still in the catalog: what the
    Tests tab opens with."""
    return encode_filter_query(list(DEFAULT_SVS_TEST_SAVED_FILTERS[0]["filters"]), screen=SVS_TESTS_SCREEN)


@svs.app_template_global()
@cache
def svs_coverage_default_f() -> list[str]:
    """The f= values of the coverage screen's default view, the endpoint platforms' rows that aren't
    retired: what the Coverage tab opens with."""
    return encode_filter_query(list(DEFAULT_SVS_COVERAGE_SAVED_FILTERS[0]["filters"]), screen=SVS_COVERAGE_SCREEN)


@svs.app_template_global()
@cache
def svs_worklist_default_f() -> list[str]:
    """The f= values of the worklist screen's default view, the tags that need a decision: what the
    Worklist tab opens with."""
    return encode_filter_query(list(DEFAULT_SVS_WORKLIST_SAVED_FILTERS[0]["filters"]), screen=SVS_WORKLIST_SCREEN)


@svs.app_template_global()
def svs_nav_count_url() -> str:
    """The API call that counts the runs that need attention, for the navigation bar."""
    return "/api/v2/svs/runs/count?" + urlencode({"f": svs_needs_attention_f()}, doseq=True)
