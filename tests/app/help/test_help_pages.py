"""The /help area: any logged-in user reads every guide, and nothing else is served from it."""

import pytest
from flask import url_for
from markupsafe import escape

from app.help.guides import GUIDE_SETS
from saq.constants import QUEUE_DEFAULT
from saq.database.util.user_management import add_user, delete_user

pytestmark = pytest.mark.integration

HELP_NAV_LINK = b'>Documentation</a>'


@pytest.fixture
def no_permissions_client(app):
    # a user holding no permission at all: the guides need only a login
    add_user(username="help_reader", email="help_reader@localhost", display_name="help_reader",
             password="TestPass123!", queue=QUEUE_DEFAULT, timezone="UTC")
    with app.test_client() as client:
        client.post(url_for("auth.login"), data={"username": "help_reader", "password": "TestPass123!"})
        yield client
    delete_user("help_reader")


def _first_image(guide_set):
    return next(p for p in sorted(guide_set.images_dir.iterdir()) if p.is_file())


def test_help_requires_login(app):
    with app.test_client() as client:
        for url in (url_for("help.help_index"),
                    url_for("help.guide", set_slug="svs", guide_slug="beginners")):
            resp = client.get(url)
            assert resp.status_code == 302
            assert "login" in resp.location


def test_help_area_serves_only_get(app):
    offenders = [(str(rule), sorted(rule.methods - {"HEAD", "OPTIONS"}))
                 for rule in app.url_map.iter_rules()
                 if str(rule).startswith("/help") and rule.methods - {"HEAD", "OPTIONS"} != {"GET"}]
    assert offenders == []


def test_index_lists_every_guide(no_permissions_client):
    resp = no_permissions_client.get(url_for("help.help_index"))
    assert resp.status_code == 200
    assert HELP_NAV_LINK in resp.data
    for guide_set in GUIDE_SETS:
        for g in guide_set.guides:
            assert url_for("help.guide", set_slug=guide_set.slug, guide_slug=g.slug).encode() in resp.data


def test_every_guide_renders_without_permissions(no_permissions_client):
    for guide_set in GUIDE_SETS:
        for g in guide_set.guides:
            resp = no_permissions_client.get(url_for("help.guide", set_slug=guide_set.slug, guide_slug=g.slug))
            assert resp.status_code == 200, g.slug
            assert b'class="help-guide"' in resp.data
            assert b'aria-current="page">' + str(escape(g.title)).encode() in resp.data


def test_pager_links_neighbours(no_permissions_client):
    guide_set = GUIDE_SETS[0]
    first, second = guide_set.guides[0], guide_set.guides[1]
    resp = no_permissions_client.get(url_for("help.guide", set_slug=guide_set.slug, guide_slug=second.slug))
    pager = resp.data.split(b'class="help-pager')[1]
    assert url_for("help.guide", set_slug=guide_set.slug, guide_slug=first.slug).encode() in pager


def test_set_redirects_to_its_first_guide(no_permissions_client):
    guide_set = GUIDE_SETS[0]
    resp = no_permissions_client.get(url_for("help.guide_set", set_slug=guide_set.slug))
    assert resp.status_code == 302
    assert resp.location.endswith(url_for("help.guide", set_slug=guide_set.slug,
                                          guide_slug=guide_set.guides[0].slug))


@pytest.mark.parametrize("path", ["/help/nope/", "/help/nope/beginners", "/help/svs/nope",
                                  "/help/svs/images", "/help/nope/images/x.png"])
def test_unknown_pages_are_404(no_permissions_client, path):
    assert no_permissions_client.get(path).status_code == 404


def test_image_is_served(no_permissions_client):
    guide_set = GUIDE_SETS[0]
    image = _first_image(guide_set)
    resp = no_permissions_client.get(url_for("help.guide_image", set_slug=guide_set.slug, filename=image.name))
    assert resp.status_code == 200
    assert resp.data == image.read_bytes()
    assert resp.mimetype.startswith("image/")


@pytest.mark.parametrize("filename", ["../beginners.md", "..%2Fbeginners.md", "%2E%2E/beginners.md",
                                      "../../guides.py", "missing.png"])
def test_image_route_stays_in_images(no_permissions_client, filename):
    assert no_permissions_client.get(f"/help/svs/images/{filename}").status_code == 404


def test_svs_tabs_and_signatures_hub_link_the_guides(web_client):
    guides = url_for("help.guide_set", set_slug="svs").encode()
    assert guides in web_client.get(url_for("svs.runs")).data
    assert guides in web_client.get(url_for("signatures.signatures_hub")).data
