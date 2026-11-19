"""The /help area: any logged-in user reads every guide, and nothing else is served from it."""

import pytest
from flask import url_for
from markupsafe import escape

from app.help.guides import GUIDE_SETS
from saq.configuration.config import get_config
from saq.constants import QUEUE_DEFAULT
from saq.database.util.alert import ALERT
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
    first, second, third = guide_set.guides[:3]
    resp = no_permissions_client.get(url_for("help.guide", set_slug=guide_set.slug, guide_slug=second.slug))
    pager = resp.data.split(b'class="help-pager')[1]
    assert url_for("help.guide", set_slug=guide_set.slug, guide_slug=first.slug).encode() in pager
    assert url_for("help.guide", set_slug=guide_set.slug, guide_slug=third.slug).encode() in pager


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
                                      "../../../guides.py", "missing.png"])
def test_image_route_stays_in_images(no_permissions_client, filename):
    assert no_permissions_client.get(f"/help/svs/images/{filename}").status_code == 404


def test_svs_tabs_and_signatures_hub_link_the_guides(web_client):
    guides = url_for("help.guide_set", set_slug="svs").encode()
    assert guides in web_client.get(url_for("svs.runs")).data
    assert guides in web_client.get(url_for("signatures.signatures_hub")).data


# ---------------------------------------------------------------------------------------- playbooks

@pytest.fixture
def playbooks_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(get_config().global_settings, "playbooks_dir", str(tmp_path))
    (tmp_path / "assets" / "oauth").mkdir(parents=True)
    (tmp_path / "assets" / "oauth" / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (tmp_path / "oauth.md").write_text(
        "---\ntitle: OAuth phishing\n---\n# OAuth phishing\n\nSee [other](other.md) ![s](assets/oauth/shot.png)\n")
    return tmp_path


def test_playbook_pages_require_login(app, playbooks_dir):
    with app.test_client() as client:
        for url in (url_for("help.playbook", name="oauth.md"),
                    url_for("help.playbook_asset", filename="oauth/shot.png")):
            resp = client.get(url)
            assert resp.status_code == 302
            assert "login" in resp.location


def test_playbook_pages_need_only_a_login(playbooks_dir, no_permissions_client):
    for url in (url_for("help.playbook", name="oauth.md"), url_for("help.playbook_asset", filename="oauth/shot.png")):
        assert no_permissions_client.get(url).status_code == 200, url


def test_playbook_page_renders(playbooks_dir, web_client):
    resp = web_client.get(url_for("help.playbook", name="oauth.md"))
    assert resp.status_code == 200
    assert url_for("help.playbook", name="other.md").encode() in resp.data
    assert url_for("help.playbook_asset", filename="oauth/shot.png").encode() in resp.data


def test_missing_playbook_is_a_404(playbooks_dir, web_client):
    assert web_client.get(url_for("help.playbook", name="nope.md")).status_code == 404


def test_playbook_symlinked_out_of_the_directory_is_a_404(playbooks_dir, web_client, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "secret.md"
    outside.write_text("# secret")
    (playbooks_dir / "link.md").symlink_to(outside)
    assert web_client.get(url_for("help.playbook", name="link.md")).status_code == 404


def test_playbook_asset_is_served_and_cannot_leave_the_directory(playbooks_dir, web_client, tmp_path_factory):
    (playbooks_dir / "secret.png").write_bytes(b"x")
    outside = tmp_path_factory.mktemp("outside") / "secret.png"
    outside.write_bytes(b"x")
    (playbooks_dir / "assets" / "oauth" / "link.png").symlink_to(outside)
    resp = web_client.get(url_for("help.playbook_asset", filename="oauth/shot.png"))
    assert resp.status_code == 200
    assert resp.data.startswith(b"\x89PNG")
    assert resp.headers["Content-Type"] == "image/png"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    for url in ("/help/playbooks/assets/../secret.png", "/help/playbooks/assets/%2e%2e/secret.png",
                url_for("help.playbook_asset", filename="oauth/link.png")):
        assert web_client.get(url).status_code == 404, url


def test_playbook_asset_serves_only_raster_images(playbooks_dir, web_client):
    for name in ("evil.svg", "page.html", "notes.txt", "noext"):
        (playbooks_dir / "assets" / "oauth" / name).write_text("<svg onload=alert(1)>")
        assert web_client.get(url_for("help.playbook_asset", filename=f"oauth/{name}")).status_code == 404, name


def test_alert_page_survives_a_playbook_that_cannot_be_rendered(web_client, root_analysis, playbooks_dir, caplog):
    (playbooks_dir / "broken.md").write_bytes(b"\xff\xfe not utf-8")
    root_analysis.playbook = "broken.md"
    root_analysis.playbook_url = "https://example.com/playbook"
    root_analysis.save()
    ALERT(root_analysis)

    resp = web_client.get(url_for("analysis.index", direct=root_analysis.uuid))
    assert resp.status_code == 200
    assert "could not be rendered" in resp.text
    assert 'href="https://example.com/playbook"' in resp.text
    assert any(r.message == "unable to render playbook" and r.exc_info for r in caplog.records)


def test_alert_page_shows_the_playbook_in_a_collapsed_section(web_client, root_analysis, playbooks_dir):
    root_analysis.playbook = "oauth.md"
    root_analysis.save()
    ALERT(root_analysis)

    resp = web_client.get(url_for("analysis.index", direct=root_analysis.uuid))
    assert resp.status_code == 200
    assert '<details class="alert-playbook">' in resp.text
    assert "OAuth phishing" in resp.text
    assert url_for("help.playbook_asset", filename="oauth/shot.png") in resp.text


def test_alert_page_names_a_missing_playbook(web_client, root_analysis, playbooks_dir):
    root_analysis.playbook = "gone.md"
    root_analysis.save()
    ALERT(root_analysis)

    resp = web_client.get(url_for("analysis.index", direct=root_analysis.uuid))
    assert resp.status_code == 200
    assert "gone.md" in resp.text
    assert "is not in the playbooks directory" in resp.text


def test_alert_page_shows_both_playbook_and_playbook_url(web_client, root_analysis, playbooks_dir):
    root_analysis.playbook = "oauth.md"
    root_analysis.playbook_url = "https://example.com/playbook"
    root_analysis.save()
    ALERT(root_analysis)

    resp = web_client.get(url_for("analysis.index", direct=root_analysis.uuid))
    assert resp.status_code == 200
    assert '<details class="alert-playbook">' in resp.text
    assert 'href="https://example.com/playbook"' in resp.text


def test_alert_page_still_links_a_legacy_playbook_url(web_client, root_analysis):
    root_analysis.playbook_url = "https://example.com/playbook"
    root_analysis.save()
    ALERT(root_analysis)

    resp = web_client.get(url_for("analysis.index", direct=root_analysis.uuid))
    assert resp.status_code == 200
    assert 'href="https://example.com/playbook"' in resp.text
    assert "alert-playbook" not in resp.text
