"""The Remediations page (/remediation/manage).

The page is a shell whose script gets everything from /api/v2/remediation (covered by
tests/aceapi_v2/remediation/); these tests assert that boundary, the remediation:read gate on the
page and the remediation:write gate on its controls.
"""

import pytest
from flask import url_for
from sqlalchemy import select

from saq.constants import F_TEST, QUEUE_DEFAULT
from saq.database.model import SavedFilter, User
from saq.database.pool import get_db
from saq.database.util.user_management import add_user, delete_user
from saq.permissions.user import add_user_permission
from saq.remediation.target import ObservableRemediationInterface, register_observable_remediation_interface

pytestmark = pytest.mark.integration


def _user(username, perms):
    user = add_user(username=username, email=f"{username}@localhost", display_name=username,
                    password="TestPass123!", queue=QUEUE_DEFAULT, timezone="UTC")
    for major, minor in perms:
        add_user_permission(user.id, major, minor)
    return username


def _login(client, username):
    client.post(url_for("auth.login"), data={"username": username, "password": "TestPass123!"})


@pytest.fixture
def remediation_reader():
    yield _user("remediation_reader", [("remediation", "read")])
    delete_user("remediation_reader")


@pytest.fixture
def remediation_writer():
    yield _user("remediation_writer", [("remediation", "read"), ("remediation", "write")])
    delete_user("remediation_writer")


@pytest.fixture
def nobody():
    yield _user("nobody", [])
    delete_user("nobody")


def test_the_blueprint_serves_only_get_pages(app):
    offenders = []
    for rule in app.url_map.iter_rules():
        if not str(rule).startswith("/remediation"):
            continue
        methods = rule.methods - {"HEAD", "OPTIONS"}
        if methods != {"GET"}:
            offenders.append((str(rule), sorted(methods)))
    assert offenders == [], f"non-GET remediation routes: {offenders}"


def test_requires_remediation_read(app, nobody):
    with app.test_client() as client:
        response = client.get(url_for("remediation.manage"))
        assert response.status_code == 302
        assert "login" in response.location

        _login(client, nobody)
        assert client.get(url_for("remediation.manage")).status_code == 403


def test_a_reader_gets_the_list_without_the_controls(app, remediation_reader):
    with app.test_client() as client:
        _login(client, remediation_reader)
        page = client.get(url_for("remediation.manage"))

    assert page.status_code == 200
    assert b'data-screen="remediations"' in page.data
    assert b'data-can-write="false"' in page.data
    assert b"js/filter_list_page.js" in page.data
    assert b"js/remediations_page.js" in page.data
    assert b"btn_add_remediation" not in page.data
    assert b'data-action="cancel"' not in page.data
    assert b"add_remediation_modal" not in page.data


def test_a_writer_gets_the_controls(app, remediation_writer):
    class _Targets(ObservableRemediationInterface):
        def get_remediation_targets(self, observable):
            return []

    register_observable_remediation_interface(F_TEST, _Targets())
    with app.test_client() as client:
        _login(client, remediation_writer)
        page = client.get(url_for("remediation.manage"))

    assert page.status_code == 200
    assert b'data-can-write="true"' in page.data
    for action in (b"restore", b"retry", b"cancel", b"delete"):
        assert b'data-action="' + action + b'"' in page.data
    assert b"add_remediation_modal" in page.data
    # the types Add Remediation offers are the ones a remediator handles
    assert f'<option value="{F_TEST}">'.encode() in page.data


def test_a_new_user_gets_the_default_saved_filters(app, remediation_reader):
    with app.test_client() as client:
        _login(client, remediation_reader)
        client.get(url_for("remediation.manage"))

    get_db().expire_all()
    names = get_db().execute(
        select(SavedFilter.name).join(User, User.id == SavedFilter.user_id)
        .where(User.username == remediation_reader, SavedFilter.screen == "remediations")).scalars().all()
    assert sorted(names) == ["Failed", "Not completed"]
