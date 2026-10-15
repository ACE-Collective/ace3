"""Smoke tests for the /svs blueprint.

The area renders pages and nothing else: the Runs tab is a shell over /api/v2/svs/runs and the
Test hosts tab over /api/v2/svs/test-hosts (tests/aceapi_v2/svs/). These tests assert that
boundary, the svs:run_read gate on the area and its nav link, and the permissions the tabs and
the bulk actions layer on top.
"""

import pytest
from flask import url_for
from sqlalchemy import select

from saq.constants import QUEUE_DEFAULT
from saq.database.model import SavedFilter, User
from saq.database.pool import get_db
from saq.database.util.user_management import add_user, delete_user
from saq.permissions.user import add_user_permission

pytestmark = pytest.mark.integration

PAGE_VIEWS = ("svs.svs_home", "svs.runs", "svs.batches", "svs.test_hosts")

# the nav link is `<a ...>SVS<span id="svs_nav_count" ...></span></a>`
SVS_NAV_LINK = b'>SVS<span id="svs_nav_count"'
TEST_HOSTS_TAB = b">Test hosts</a>"


def _make_user(username, perms):
    user = add_user(
        username=username,
        email=f"{username}@localhost",
        display_name=username,
        password="TestPass123!",
        queue=QUEUE_DEFAULT,
        timezone="UTC",
    )
    for major, minor in perms:
        add_user_permission(user.id, major, minor)
    return user


def _login(client, username):
    client.post(url_for("auth.login"), data={"username": username, "password": "TestPass123!"})


def _saved_filter_names(username, screen):
    get_db().expire_all()
    return sorted(get_db().execute(
        select(SavedFilter.name).join(User, User.id == SavedFilter.user_id)
        .where(User.username == username, SavedFilter.screen == screen)).scalars().all())


def _list_pages():
    return url_for("svs.runs"), url_for("svs.batches")


@pytest.fixture
def run_reader():
    _make_user("svs_reader", [("svs", "run_read")])
    yield "svs_reader"
    delete_user("svs_reader")


@pytest.fixture
def run_manager():
    _make_user("svs_manager", [("svs", "run_read"), ("svs", "run_manage")])
    yield "svs_manager"
    delete_user("svs_manager")


@pytest.fixture
def svs_admin():
    _make_user("svs_admin", [("svs", "run_read"), ("svs", "admin")])
    yield "svs_admin"
    delete_user("svs_admin")


class TestSVSIsPagesOnly:
    def test_page_views_exist(self, app):
        for endpoint in PAGE_VIEWS:
            assert endpoint in app.view_functions, endpoint

    def test_svs_blueprint_serves_only_get_pages(self, app):
        offenders = []
        for rule in app.url_map.iter_rules():
            if not str(rule).startswith("/svs"):
                continue
            methods = rule.methods - {"HEAD", "OPTIONS"}
            if methods != {"GET"}:
                offenders.append((str(rule), sorted(methods)))
        assert offenders == [], f"non-GET svs routes: {offenders}"


class TestRunsPages:
    def test_requires_auth(self, app):
        with app.test_client() as client:
            resp = client.get(url_for("svs.runs"))
            assert resp.status_code == 302
            assert "login" in resp.location

    def test_home_opens_the_runs(self, app, run_reader):
        with app.test_client() as client:
            _login(client, run_reader)
            resp = client.get(url_for("svs.svs_home"))
            assert resp.status_code == 302
            assert resp.location.endswith(url_for("svs.runs"))

    def test_pages_are_driven_by_the_v2_api(self, app, run_reader):
        with app.test_client() as client:
            _login(client, run_reader)
            for view, page_url in zip(("runs", "batches"), _list_pages()):
                page = client.get(page_url)
                assert page.status_code == 200, page_url
                data = page.data
                assert f'data-view="{view}"'.encode() in data
                assert b'data-api="/api/v2/svs/runs"' in data
                assert b'data-screen="svs_runs"' in data
                # Runs opens on Needs attention
                assert b"""data-default-f='["needs_attention:true"]'""" in data
                assert b'data-tz="UTC"' in data
                # the list controller and the saved filters load before the page's script
                assert (data.index(b"ace_api.js") < data.index(b"saved_filters.js")
                        < data.index(b"filter_list_page.js") < data.index(b"svs_runs.js"))
                assert b'id="save_filter_modal"' in data and b'id="manage_filters_modal"' in data
                assert SVS_NAV_LINK in data

    def test_rows_link_nowhere_until_the_run_page_exists(self, app, run_reader):
        with app.test_client() as client:
            _login(client, run_reader)
            assert b'data-run-url=""' in client.get(url_for("svs.runs")).data

    def test_bulk_actions_follow_run_manage(self, app, run_reader, run_manager):
        with app.test_client() as client:
            _login(client, run_reader)
            page = client.get(url_for("svs.runs")).data
            assert b'data-can-manage="false"' in page
            assert b'id="svs_runs_action_modal"' not in page and b'id="svs_runs_take_modal"' not in page

        with app.test_client() as client:
            _login(client, run_manager)
            page = client.get(url_for("svs.runs")).data
            assert b'data-can-manage="true"' in page
            assert b'id="svs_runs_action_modal"' in page and b'id="svs_runs_take_modal"' in page
            # batches are read-only
            assert b'id="svs_runs_action_modal"' not in client.get(url_for("svs.batches")).data

    def test_the_list_pages_seed_the_default_saved_filters_once(self, app, run_reader):
        assert _saved_filter_names(run_reader, "svs_runs") == []
        with app.test_client() as client:
            _login(client, run_reader)
            client.get(url_for("svs.batches"))
            assert _saved_filter_names(run_reader, "svs_runs") == ["Needs attention", "Started"]
            client.get(url_for("svs.runs"))
            assert _saved_filter_names(run_reader, "svs_runs") == ["Needs attention", "Started"]


class TestNavigation:
    def test_the_svs_entry_replaces_detectops(self, app, run_reader):
        with app.test_client() as client:
            _login(client, run_reader)
            page = client.get(url_for("auth.change_password")).data
            assert SVS_NAV_LINK in page
            # the count of the runs that need attention, read by svs_nav.js; not a badge
            assert b'data-count-url="/api/v2/svs/runs/count?f=needs_attention%3Atrue"' in page
            assert b"svs_nav.js" in page
            assert b"DetectOps" not in page


class TestTestHostsTab:
    def test_only_an_admin_gets_the_tab(self, app, run_reader, svs_admin):
        with app.test_client() as client:
            _login(client, run_reader)
            assert TEST_HOSTS_TAB not in client.get(url_for("svs.runs")).data
            assert client.get(url_for("svs.test_hosts")).status_code == 403

        with app.test_client() as client:
            _login(client, svs_admin)
            assert TEST_HOSTS_TAB in client.get(url_for("svs.runs")).data
            page = client.get(url_for("svs.test_hosts"))
            assert page.status_code == 200
            assert b'data-api="/api/v2/svs/test-hosts"' in page.data
            assert b"svs_test_hosts.js" in page.data
            for platform in (b"windows", b"linux", b"macos"):
                assert b'<option value="' + platform + b'">' in page.data


class TestSVSAreaGate:
    def test_without_run_read_the_area_is_closed(self, app):
        _make_user("svs_none", [("alert", "read")])
        try:
            with app.test_client() as client:
                _login(client, "svs_none")
                for endpoint in PAGE_VIEWS:
                    assert client.get(url_for(endpoint)).status_code == 403, endpoint

                # the nav link and its count are gated too, so they are absent on a page they can load
                page = client.get(url_for("auth.change_password"))
                assert page.status_code == 200
                assert SVS_NAV_LINK not in page.data
                assert b"svs_nav.js" not in page.data
        finally:
            delete_user("svs_none")

    def test_an_admin_without_run_read_is_kept_out(self, app):
        # svs:admin alone opens nothing here: the area's gate is run_read
        _make_user("svs_admin_only", [("svs", "admin")])
        try:
            with app.test_client() as client:
                _login(client, "svs_admin_only")
                assert client.get(url_for("svs.test_hosts")).status_code == 403
        finally:
            delete_user("svs_admin_only")

    def test_superuser_sees_the_area(self, app, web_client):
        assert SVS_NAV_LINK in web_client.get(url_for("svs.runs")).data
        for page_url in _list_pages() + (url_for("svs.test_hosts"),):
            assert web_client.get(page_url).status_code == 200, page_url
