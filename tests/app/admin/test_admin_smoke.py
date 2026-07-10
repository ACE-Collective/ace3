"""Smoke tests for the /admin blueprint.

The admin blueprint renders pages and nothing else: every JSON endpoint the admin pages use lives in
aceapi_v2 and is called directly from the browser. These tests assert that boundary holds, plus that
the pages render behind their permission gates. The behaviour behind those endpoints is covered by
tests/aceapi_v2/users/ and tests/aceapi_v2/detection/.
"""

import pytest
from flask import url_for

from saq.constants import QUEUE_DEFAULT
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

# the page views that legitimately remain
PAGE_VIEWS = ("admin.admin_hub", "admin.manage_users", "admin.detection_settings")


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
    def test_page_views_exist(self, app):
        for endpoint in PAGE_VIEWS:
            assert endpoint in app.view_functions, endpoint

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
                ("admin.detection_settings", b"Observable Detection Settings"),
            ):
                resp = client.get(url_for(endpoint))
                assert resp.status_code == 200, endpoint
                assert needle in resp.data, endpoint

    def test_pages_are_permission_gated(self, app):
        noperms = add_user(
            username="noperms_admin",
            email="noperms_admin@localhost",
            display_name="No Perms",
            password="TestPass123!",
            queue=QUEUE_DEFAULT,
            timezone="UTC",
        )
        try:
            with app.test_client() as client:
                client.post(url_for("auth.login"), data={
                    "username": "noperms_admin", "password": "TestPass123!",
                })
                for endpoint in ("admin.manage_users", "admin.detection_settings"):
                    assert client.get(url_for(endpoint)).status_code in (302, 403), endpoint
        finally:
            delete_user("noperms_admin")

    def test_pages_point_at_the_v2_api(self, app, admin_user):
        """The rendered pages must call aceapi_v2, not a Flask route."""
        with app.test_client() as client:
            client.post(url_for("auth.login"), data={
                "username": "adminuser", "password": "TestPass123!",
            })
            users_page = client.get(url_for("admin.manage_users")).data
            assert b"/ace/admin/users/add" not in users_page
            detection_page = client.get(url_for("admin.detection_settings")).data
            assert b"/ace/admin/detection/toggle" not in detection_page
