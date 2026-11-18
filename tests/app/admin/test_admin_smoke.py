"""Smoke tests for the /admin blueprint.

The admin blueprint renders pages and nothing else: every JSON endpoint the admin pages use lives in
aceapi_v2 and is called directly from the browser. These tests assert that boundary holds, plus that
the pages render behind their permission gates. The behaviour behind those endpoints is covered by
tests/aceapi_v2/users/ and tests/aceapi_v2/detection/.
"""

from datetime import datetime

import pytest
from flask import url_for

from saq.configuration.config import get_config
from saq.constants import QUEUE_DEFAULT
from saq.database.model import Observable, ObservableComment
from saq.database.pool import get_db
from saq.database.util.observable_detection import create_observable_detection, resolve_observable_identity
from saq.database.util.user_management import add_user, delete_user
from saq.permissions.user import add_user_permission

pytestmark = pytest.mark.integration

# every JSON endpoint the admin pages once served from Flask, now served by aceapi_v2
REMOVED_FLASK_ENDPOINTS = (
    "admin.get_user_details",
    "admin.add_user",
    "admin.edit_users",
    "admin.add_auth_group",
    "admin.delete_auth_groups",
    "admin.add_permission",
    "admin.delete_permission",
    "admin.generate_api_key",
    "admin.revoke_api_key",
    "admin.detection_toggle",
    "admin.detection_expiration",
)


@pytest.fixture
def admin_user():
    user = add_user(
        username="adminuser",
        email="adminuser@localhost",
        display_name="Admin User",
        password="TestPass123!",
        queue=QUEUE_DEFAULT,
        timezone="UTC",
    )
    add_user_permission(user.id, "*", "*")
    yield user
    delete_user("adminuser")


class TestAdminIsPagesOnly:
    def test_json_endpoints_are_not_served_by_flask(self, app):
        """New endpoints belong in aceapi_v2. Nothing here may serve JSON."""
        for endpoint in REMOVED_FLASK_ENDPOINTS:
            assert endpoint not in app.view_functions, endpoint

    def test_admin_blueprint_serves_only_get_pages(self, app):
        """No POST/PATCH/DELETE route may exist under /admin."""
        offenders = []
        for rule in app.url_map.iter_rules():
            if not str(rule).startswith("/admin"):
                continue
            methods = rule.methods - {"HEAD", "OPTIONS"}
            if methods != {"GET"}:
                offenders.append((str(rule), sorted(methods)))
        assert offenders == [], f"non-GET admin routes remain: {offenders}"

    def test_old_auth_blueprint_endpoints_are_gone(self, app):
        for endpoint in ("auth.manage_users", "auth.edit_users", "auth.add_user", "auth.get_own_api_key"):
            assert endpoint not in app.view_functions
        # self-service auth endpoints remain
        for endpoint in ("auth.login", "auth.logout", "auth.change_password"):
            assert endpoint in app.view_functions


class TestAdminPagesRender:
    def test_hub_requires_auth(self, app):
        with app.test_client() as client:
            resp = client.get(url_for("admin.admin_hub"))
            assert resp.status_code == 302
            assert "login" in resp.location

    def test_pages_render_for_permitted_user(self, app, admin_user):
        with app.test_client() as client:
            client.post(url_for("auth.login"), data={
                "username": "adminuser", "password": "TestPass123!",
            })
            for endpoint, needle in (
                ("admin.admin_hub", b"Administration"),
                ("admin.manage_users", b"User Management"),
                ("admin.detection_settings", b"Observable Detections"),
                ("admin.manage_secrets", b"Encrypted Secrets"),
                ("admin.cli_console", b"admin_cli.js"),
            ):
                resp = client.get(url_for(endpoint))
                assert resp.status_code == 200, endpoint
                assert needle in resp.data, endpoint

    def test_detection_page_marks_edited_comments(self, app, admin_user):
        """An observable comment changed after it was made says when; an unedited one does not."""
        # comments by admin_user would block deleting it at teardown
        user_id = get_config().global_settings.automation_user_id
        create_observable_detection("ipv4", "192.0.2.10", user_id)
        identity = resolve_observable_identity("ipv4", "192.0.2.10")
        db = get_db()
        observable = Observable(type=identity.type, sha256=identity.value_sha256,
                                value=identity.value.encode("utf8"))
        db.add(observable)
        db.flush()
        db.add(ObservableComment(user_id=user_id, observable_id=observable.id, comment="never touched"))
        db.add(ObservableComment(user_id=user_id, observable_id=observable.id, comment="reworded",
                                 edited_at=datetime(2026, 5, 6, 7, 8, 9)))
        db.commit()

        with app.test_client() as client:
            client.post(url_for("auth.login"), data={
                "username": "adminuser", "password": "TestPass123!",
            })
            resp = client.get(url_for("admin.detection_settings"), query_string={"q": "192.0.2.10"})
            assert resp.status_code == 200
            body = resp.data.decode("utf-8")
            assert "never touched" in body
            assert "reworded" in body
            assert "(edited 2026-05-06 07:08)" in body
            assert body.count("(edited ") == 1

    def test_pages_point_at_the_v2_api(self, app, admin_user):
        """The rendered pages must call aceapi_v2, not a Flask route. The calls are made by the
        scripts the pages load."""
        with app.test_client() as client:
            client.post(url_for("auth.login"), data={
                "username": "adminuser", "password": "TestPass123!",
            })
            users_page = client.get(url_for("admin.manage_users")).data
            assert b"/ace/admin/users/add" not in users_page
            detection_page = client.get(url_for("admin.detection_settings")).data
            assert b"/ace/admin/detection/toggle" not in detection_page

            for page, script, api in (
                (users_page, "js/manage_users.js", b'"/api/v2/users"'),
                (detection_page, "js/admin_detection.js", b'"/api/v2/detection"'),
            ):
                script_url = url_for("static", filename=script)
                assert script_url.encode() in page, script
                assert api in client.get(script_url).data, script


# The nav link is `<a ... >Admin</a>`; the hub heading is "Administration", so this needle matches
# only the nav link, not the hub page's own title.
ADMIN_NAV_LINK = b">Admin</a>"


class TestAdminAreaGate:
    """`admin:read` is the umbrella gate for the whole area; each page layers its own permission.

    Matrix: viewing a sub-page needs `admin:read` AND that module's read permission. Without
    `admin:read` the user is fully locked out of every /admin route (no deep-link gap) and does not
    see the nav link.
    """

    def _make_user(self, username, perms):
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

    def _login(self, client, username):
        client.post(url_for("auth.login"), data={"username": username, "password": "TestPass123!"})

    def test_admin_read_only_enters_area_but_no_module(self, app):
        """admin:read alone: nav link + hub, but every sub-page is 403 and the hub shows no tiles."""
        self._make_user("gate_admin_only", [("admin", "read")])
        try:
            with app.test_client() as client:
                self._login(client, "gate_admin_only")

                hub = client.get(url_for("admin.admin_hub"))
                assert hub.status_code == 200
                assert ADMIN_NAV_LINK in hub.data
                assert b"do not have access to any administration" in hub.data

                assert client.get(url_for("admin.manage_users")).status_code == 403
                assert client.get(url_for("admin.detection_settings")).status_code == 403
                assert client.get(url_for("admin.manage_secrets")).status_code == 403
                assert client.get(url_for("admin.cli_console")).status_code == 403
        finally:
            delete_user("gate_admin_only")

    def test_admin_read_plus_module_read_opens_that_module_only(self, app):
        """admin:read + detection:read: hub shows only the Detection tile; Users stays 403."""
        self._make_user("gate_det_admin", [("admin", "read"), ("detection", "read")])
        try:
            with app.test_client() as client:
                self._login(client, "gate_det_admin")

                hub = client.get(url_for("admin.admin_hub"))
                assert hub.status_code == 200
                assert b"Observables" in hub.data           # detection tile present
                assert b"Users &amp; Roles" not in hub.data  # users tile absent

                assert client.get(url_for("admin.detection_settings")).status_code == 200
                assert client.get(url_for("admin.manage_users")).status_code == 403
        finally:
            delete_user("gate_det_admin")

    def test_module_read_without_admin_read_is_fully_locked_out(self, app):
        """detection:read but NOT admin:read: every /admin route 403, and no nav link."""
        self._make_user("gate_no_admin", [("detection", "read")])
        try:
            with app.test_client() as client:
                self._login(client, "gate_no_admin")

                assert client.get(url_for("admin.admin_hub")).status_code == 403
                assert client.get(url_for("admin.detection_settings")).status_code == 403
                assert client.get(url_for("admin.manage_users")).status_code == 403

                # the nav link is gated on admin:read, so it must be absent on a page they can load
                page = client.get(url_for("auth.change_password"))
                assert page.status_code == 200
                assert ADMIN_NAV_LINK not in page.data
        finally:
            delete_user("gate_no_admin")

    def test_superuser_sees_everything(self, app, admin_user):
        """`*:*` matches admin:read via wildcard, so a superuser has full access."""
        with app.test_client() as client:
            self._login(client, "adminuser")

            hub = client.get(url_for("admin.admin_hub"))
            assert hub.status_code == 200
            assert ADMIN_NAV_LINK in hub.data
            assert client.get(url_for("admin.manage_users")).status_code == 200
            assert client.get(url_for("admin.detection_settings")).status_code == 200
