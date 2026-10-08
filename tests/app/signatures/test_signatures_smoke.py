"""Smoke tests for the /signatures blueprint.

Like /admin, the area renders pages and nothing else: the Yara QA Results page is a shell whose
script gets everything from /api/v2/signatures/yara-qa (covered by tests/aceapi_v2/yara_qa/), and
the Samples pages are shells over /api/v2/svs/samples (tests/aceapi_v2/svs/). These tests assert
that boundary, and the signature:read gate on the area and its nav link.
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

PAGE_VIEWS = ("signatures.signatures_hub", "signatures.yara_qa", "signatures.samples", "signatures.sample_detail")

SHA256 = "a" * 64
RULE_UUID = "00000000-0000-0000-0000-000000000001"

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


def _sample_pages():
    return (url_for("signatures.samples"),
            url_for("signatures.sample_detail", sha256=SHA256, rule_uuid=RULE_UUID))


def _saved_filter_names(username, screen):
    get_db().expire_all()
    return sorted(get_db().execute(
        select(SavedFilter.name).join(User, User.id == SavedFilter.user_id)
        .where(User.username == username, SavedFilter.screen == screen)).scalars().all())


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


class TestSamplesPages:
    def test_hub_shows_the_samples_card(self, app, signature_reader):
        with app.test_client() as client:
            _login(client, signature_reader)
            hub = client.get(url_for("signatures.signatures_hub")).data
            assert b"<h5 class=\"card-title\">Samples</h5>" in hub
            assert url_for("signatures.samples").encode() in hub

    def test_pages_render_for_a_signature_reader(self, app, signature_reader):
        with app.test_client() as client:
            _login(client, signature_reader)
            for page_url in _sample_pages():
                page = client.get(page_url)
                assert page.status_code == 200, page_url
                assert b'data-api="/api/v2/svs/samples"' in page.data
                assert b'data-screen="svs_samples"' in page.data
                assert b'data-tz="UTC"' in page.data
                assert b"signatures_samples.js" in page.data
                assert b"verdicts.js" in page.data

    def test_list_page_is_a_filter_list_page_with_saved_filters(self, app, signature_reader):
        with app.test_client() as client:
            _login(client, signature_reader)
            page = client.get(url_for("signatures.samples")).data
            for script in (b"ace_api.js", b"saved_filters.js", b"filter_list_page.js", b"signatures_samples.js"):
                assert script in page
            # the order matters: each script uses the ones before it
            positions = [page.index(script) for script in (b"js/ace_api.js", b"js/saved_filters.js", b"js/verdicts.js",
                                                             b"js/filter_list_page.js", b"js/signatures_samples.js")]
            assert positions == sorted(positions)
            assert b'id="save_filter_modal"' in page
            assert b'id="manage_filters_modal"' in page

    def test_detail_page_carries_the_sample_key(self, app, signature_reader):
        with app.test_client() as client:
            _login(client, signature_reader)
            page = client.get(url_for("signatures.sample_detail", sha256=SHA256, rule_uuid=RULE_UUID)).data
            assert f'data-sha256="{SHA256}"'.encode() in page
            assert f'data-rule-uuid="{RULE_UUID}"'.encode() in page
            # one sample has no list and no saved filters
            assert b"filter_list_page.js" not in page
            assert b'id="save_filter_modal"' not in page

    def test_detail_page_escapes_the_key(self, app, signature_reader):
        # the key is validated by the API, not the page, so the page must never trust it
        with app.test_client() as client:
            _login(client, signature_reader)
            page = client.get(url_for("signatures.sample_detail", sha256='x"><script>', rule_uuid=RULE_UUID))
            assert page.status_code == 200
            assert b'x"><script>' not in page.data

    def test_download_controls_follow_signature_download(self, app, signature_reader, signature_downloader):
        with app.test_client() as client:
            _login(client, signature_reader)
            for page_url in _sample_pages():
                assert b'data-can-download="false"' in client.get(page_url).data

        with app.test_client() as client:
            _login(client, signature_downloader)
            for page_url in _sample_pages():
                assert b'data-can-download="true"' in client.get(page_url).data

    def test_list_page_seeds_the_default_saved_filters_once(self, app, signature_reader):
        assert _saved_filter_names(signature_reader, "svs_samples") == []
        with app.test_client() as client:
            _login(client, signature_reader)
            client.get(url_for("signatures.samples"))
            assert _saved_filter_names(signature_reader, "svs_samples") == ["Conflicted", "Missing data"]

            client.get(url_for("signatures.samples"))
            assert _saved_filter_names(signature_reader, "svs_samples") == ["Conflicted", "Missing data"]

        # the alert screen's defaults are the manage page's business
        assert _saved_filter_names(signature_reader, "alerts") == []


class TestSignaturesAreaGate:
    def test_without_signature_read_the_area_is_closed(self, app):
        _make_user("sig_none", [("alert", "read")])
        try:
            with app.test_client() as client:
                _login(client, "sig_none")
                assert client.get(url_for("signatures.signatures_hub")).status_code == 403
                assert client.get(url_for("signatures.yara_qa")).status_code == 403
                for page_url in _sample_pages():
                    assert client.get(page_url).status_code == 403, page_url

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
        for page_url in _sample_pages():
            assert web_client.get(page_url).status_code == 200, page_url
