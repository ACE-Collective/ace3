# vim: sw=4:ts=4:et:cc=120

"""The File Collections page (/file_collection/manage).

The page is a shell whose script gets everything from /api/v2/file-collections (covered by
tests/aceapi_v2/file_collection/); these tests assert that boundary, the file_collection:read gate
on the page and the file_collection:write gate on its controls.
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


def _user(username, perms):
    user = add_user(username=username, email=f"{username}@localhost", display_name=username,
                    password="TestPass123!", queue=QUEUE_DEFAULT, timezone="UTC")
    for major, minor in perms:
        add_user_permission(user.id, major, minor)
    return username


def _login(client, username):
    client.post(url_for("auth.login"), data={"username": username, "password": "TestPass123!"})


@pytest.fixture
def collection_reader():
    yield _user("collection_reader", [("file_collection", "read")])
    delete_user("collection_reader")


@pytest.fixture
def collection_writer():
    yield _user("collection_writer", [("file_collection", "read"), ("file_collection", "write")])
    delete_user("collection_writer")


@pytest.fixture
def nobody():
    yield _user("nobody", [])
    delete_user("nobody")


def test_the_blueprint_serves_only_get_pages(app):
    offenders = []
    for rule in app.url_map.iter_rules():
        if not str(rule).startswith("/file_collection"):
            continue
        methods = rule.methods - {"HEAD", "OPTIONS"}
        if methods != {"GET"}:
            offenders.append((str(rule), sorted(methods)))
    assert offenders == [], f"non-GET file collection routes: {offenders}"


def test_requires_file_collection_read(app, nobody):
    with app.test_client() as client:
        response = client.get(url_for("file_collection.manage"))
        assert response.status_code == 302
        assert "login" in response.location

        _login(client, nobody)
        assert client.get(url_for("file_collection.manage")).status_code == 403


def test_a_reader_gets_the_list_without_the_controls(app, collection_reader):
    with app.test_client() as client:
        _login(client, collection_reader)
        page = client.get(url_for("file_collection.manage"))

    assert page.status_code == 200
    assert b'data-screen="file_collections"' in page.data
    assert b'data-can-write="false"' in page.data
    assert b"js/filter_list_page.js" in page.data
    assert b"js/file_collections_page.js" in page.data
    assert b'data-action="' not in page.data


def test_a_writer_gets_the_controls(app, collection_writer):
    with app.test_client() as client:
        _login(client, collection_writer)
        page = client.get(url_for("file_collection.manage"))

    assert page.status_code == 200
    assert b'data-can-write="true"' in page.data
    for action in (b"retry", b"cancel", b"delete"):
        assert b'data-action="' + action + b'"' in page.data


def test_a_new_user_gets_the_default_saved_filters(app, collection_reader):
    with app.test_client() as client:
        _login(client, collection_reader)
        client.get(url_for("file_collection.manage"))

    get_db().expire_all()
    names = get_db().execute(
        select(SavedFilter.name).join(User, User.id == SavedFilter.user_id)
        .where(User.username == collection_reader, SavedFilter.screen == "file_collections")).scalars().all()
    assert sorted(names) == ["Failed", "Not completed"]
