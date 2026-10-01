"""Smoke tests for the /signatures blueprint.

Like /admin, the area renders pages and nothing else: the Yara QA Results page is a shell whose
script gets everything from /api/v2/signatures/yara-qa (covered by tests/aceapi_v2/yara_qa/). These
tests assert that boundary, and the signature:read gate on the area and its nav link.
"""

import pytest
from flask import url_for

from saq.constants import QUEUE_DEFAULT
from saq.database.util.user_management import add_user, delete_user
from saq.permissions.user import add_user_permission

pytestmark = pytest.mark.integration

PAGE_VIEWS = ("signatures.signatures_hub", "signatures.yara_qa")

# the nav link is `<a ... >Signatures</a>`; the hub heading is an <h2>, so this matches only the link
SIGNATURES_NAV_LINK = b">Signatures</a>"


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


@pytest.fixture
def signature_reader():
    _make_user("sig_reader", [("signature", "read")])
    yield "sig_reader"
    delete_user("sig_reader")


@pytest.fixture
def signature_downloader():
    _make_user("sig_downloader", [("signature", "read"), ("signature", "download")])
    yield "sig_downloader"
    delete_user("sig_downloader")


class TestSignaturesIsPagesOnly:
    def test_page_views_exist(self, app):
        for endpoint in PAGE_VIEWS:
            assert endpoint in app.view_functions, endpoint

    def test_signatures_blueprint_serves_only_get_pages(self, app):
        offenders = []
        for rule in app.url_map.iter_rules():
            if not str(rule).startswith("/signatures"):
                continue
            methods = rule.methods - {"HEAD", "OPTIONS"}
            if methods != {"GET"}:
                offenders.append((str(rule), sorted(methods)))
        assert offenders == [], f"non-GET signatures routes: {offenders}"


class TestSignaturesPages:
    def test_hub_requires_auth(self, app):
        with app.test_client() as client:
            resp = client.get(url_for("signatures.signatures_hub"))
            assert resp.status_code == 302
            assert "login" in resp.location

    def test_pages_render_for_a_signature_reader(self, app, signature_reader):
        with app.test_client() as client:
            _login(client, signature_reader)

            hub = client.get(url_for("signatures.signatures_hub"))
            assert hub.status_code == 200
            assert SIGNATURES_NAV_LINK in hub.data
            assert b"Yara QA Results" in hub.data
            assert url_for("signatures.yara_qa").encode() in hub.data

            page = client.get(url_for("signatures.yara_qa"))
            assert page.status_code == 200
            assert b"Yara QA Results" in page.data

    def test_page_is_driven_by_the_v2_api(self, app, signature_reader):
        with app.test_client() as client:
            _login(client, signature_reader)
            page = client.get(url_for("signatures.yara_qa")).data
            assert b'data-api="/api/v2/signatures/yara-qa"' in page
            assert b"signatures_yara_qa.js" in page

    def test_download_controls_follow_signature_download(self, app, signature_reader, signature_downloader):
        with app.test_client() as client:
            _login(client, signature_reader)
            assert b'data-can-download="false"' in client.get(url_for("signatures.yara_qa")).data

        with app.test_client() as client:
            _login(client, signature_downloader)
            assert b'data-can-download="true"' in client.get(url_for("signatures.yara_qa")).data


class TestSignaturesAreaGate:
    def test_without_signature_read_the_area_is_closed(self, app):
        _make_user("sig_none", [("alert", "read")])
        try:
            with app.test_client() as client:
                _login(client, "sig_none")
                assert client.get(url_for("signatures.signatures_hub")).status_code == 403
                assert client.get(url_for("signatures.yara_qa")).status_code == 403

                # the nav link is gated too, so it is absent on a page they can load
                page = client.get(url_for("auth.change_password"))
                assert page.status_code == 200
                assert SIGNATURES_NAV_LINK not in page.data
        finally:
            delete_user("sig_none")

    def test_superuser_sees_the_area(self, app, web_client):
        hub = web_client.get(url_for("signatures.signatures_hub"))
        assert hub.status_code == 200
        assert SIGNATURES_NAV_LINK in hub.data
        assert web_client.get(url_for("signatures.yara_qa")).status_code == 200
