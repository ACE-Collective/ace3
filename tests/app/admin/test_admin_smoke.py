"""Smoke tests for the /admin blueprint and its bridge to the aceapi_v2 users service."""

import json

import pytest
from flask import url_for

from saq.constants import QUEUE_DEFAULT
from saq.database import get_db
from saq.database.model import AuthGroup, AuthUserPermission, User
from saq.database.util.user_management import add_user, delete_user
from saq.permissions.user import add_user_permission

pytestmark = pytest.mark.integration


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
    add_user_permission(user.id, "user", "write")
    yield user
    delete_user("adminuser")


class TestAdminRouting:
    def test_migrated_endpoints_exist_and_old_ones_gone(self, app):
        with app.test_request_context():
            assert url_for("admin.manage_users")
            assert url_for("admin.add_user")
        # the old auth-blueprint management endpoints must be fully removed
        for endpoint in ("auth.manage_users", "auth.edit_users", "auth.add_user", "auth.add_permission"):
            assert endpoint not in app.view_functions
        # self-service auth endpoints remain
        for endpoint in ("auth.login", "auth.logout", "auth.change_password"):
            assert endpoint in app.view_functions

    def test_admin_hub_requires_auth(self, app):
        with app.test_client() as client:
            resp = client.get(url_for("admin.admin_hub"))
            assert resp.status_code == 302
            assert "login" in resp.location


class TestAdminEndToEnd:
    def test_create_user_through_bridge(self, app, admin_user):
        """Full path: Flask admin view -> sync bridge -> async service -> committed write."""
        with app.test_client() as client:
            client.post(url_for("auth.login"), data={
                "username": "adminuser", "password": "TestPass123!",
            })
            resp = client.post(
                url_for("admin.add_user"),
                data=json.dumps({
                    "username": "e2e_created",
                    "email": "e2e_created@localhost",
                    "display_name": "E2E",
                    "password": "NewPass123!",
                    "queue": "default",
                    "timezone": "UTC",
                    "permissions": [{"major": "alert", "minor": "read", "effect": "ALLOW"}],
                    "groups": [],
                }),
                content_type="application/json",
            )
            assert resp.status_code == 200
            try:
                created = get_db().query(User).filter(User.username == "e2e_created").first()
                assert created is not None
                assert created.verify_password("NewPass123!")
                perm = get_db().query(AuthUserPermission).filter(
                    AuthUserPermission.user_id == created.id,
                    AuthUserPermission.major == "alert",
                ).first()
                assert perm is not None
            finally:
                delete_user("e2e_created")

    def test_blank_username_is_rejected(self, app, admin_user):
        """Regression: submitting the Add User modal with blank fields created an empty user row."""
        with app.test_client() as client:
            client.post(url_for("auth.login"), data={
                "username": "adminuser", "password": "TestPass123!",
            })
            resp = client.post(
                url_for("admin.add_user"),
                data=json.dumps({
                    "username": "", "email": "", "display_name": "",
                    "queue": "default", "timezone": "UTC",
                    "permissions": [{"major": "user", "minor": "read", "effect": "ALLOW"}],
                    "groups": [],
                }),
                content_type="application/json",
            )
            assert resp.status_code == 400
            # and nothing was written
            assert get_db().query(User).filter(User.username == "").first() is None

    def test_blank_group_name_redirects_instead_of_erroring(self, app, admin_user):
        """The add-group form posts natively, so a blank name should flash+redirect, not 400 JSON."""
        with app.test_client() as client:
            client.post(url_for("auth.login"), data={
                "username": "adminuser", "password": "TestPass123!",
            })
            before = get_db().query(AuthGroup).count()
            resp = client.post(url_for("admin.add_auth_group"), data={"add_auth_group_name": "   "})
            assert resp.status_code == 302
            assert resp.location.endswith(url_for("admin.manage_users"))
            assert get_db().query(AuthGroup).count() == before

    def test_write_requires_user_write_permission(self, app):
        """A logged-in user without user:write is forbidden from admin mutations."""
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
                resp = client.post(
                    url_for("admin.add_user"),
                    data=json.dumps({"username": "nope", "email": "nope@localhost"}),
                    content_type="application/json",
                )
                assert resp.status_code in (302, 403)
        finally:
            delete_user("noperms_admin")
