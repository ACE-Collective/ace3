"""The /feeds GUI pages and the feed watch alert (docs/FEED_WATCHES.md). The pages are shells over
/api/v2/feeds and /api/v2/feed-watches (covered in tests/aceapi_v2/); these tests check the permission
gates, the nav link, and what a feed watch alert shows."""

import pytest
from flask import url_for

from saq.constants import ALERT_TYPE_FEED_WATCH, QUEUE_DEFAULT
from saq.database.util.alert import ALERT
from saq.database.util.user_management import add_user, delete_user
from saq.permissions.user import add_user_permission

PASSWORD = "TestPass123!"


@pytest.fixture
def make_user():
    created = []

    def make(username, perms):
        user = add_user(username=username, email=f"{username}@localhost", display_name=username, password=PASSWORD,
                        queue=QUEUE_DEFAULT, timezone="UTC")
        for major, minor in perms:
            add_user_permission(user.id, major, minor)
        created.append(username)
        return user

    yield make
    for username in created:
        delete_user(username)


def _login(client, username):
    client.post(url_for("auth.login"), data={"username": username, "password": PASSWORD})


@pytest.mark.integration
@pytest.mark.parametrize("endpoint, kwargs, permission", [
    ("feeds.feeds_page", {}, ("feed", "read")),
    ("feeds.watches_page", {}, ("feed_watch", "read")),
    ("feeds.replay_page", {}, ("feed_watch", "read")),
    ("feeds.evaluation", {"watch_id": 1}, ("feed_watch", "read")),
])
def test_each_page_needs_its_permission(app, make_user, endpoint, kwargs, permission):
    make_user("feeds_allowed", [permission, ("alert", "read")])
    make_user("feeds_denied", [("alert", "read")])
    with app.test_client() as client:
        _login(client, "feeds_denied")
        assert client.get(url_for(endpoint, **kwargs)).status_code == 403
    with app.test_client() as client:
        _login(client, "feeds_allowed")
        response = client.get(url_for(endpoint, **kwargs))
        assert response.status_code == 200
        assert b"js/feeds.js" in response.data


@pytest.mark.integration
def test_the_nav_link_shows_with_either_permission(app, make_user):
    make_user("feeds_watcher", [("feed_watch", "read")])
    make_user("feeds_reader", [("feed", "read")])
    make_user("feeds_nobody", [("alert", "read")])
    for username, target in (("feeds_watcher", url_for("feeds.watches_page")), ("feeds_reader", url_for("feeds.feeds_page")),
                             ("feeds_nobody", None)):
        with app.test_client() as client:
            _login(client, username)
            page = client.get(url_for("help.help_index")).data.decode()
            if target is None:
                assert ">Feeds</a>" not in page
            else:
                assert f'href="{target}">Feeds</a>' in page


@pytest.mark.integration
def test_the_write_controls_follow_the_write_permission(app, make_user):
    make_user("feeds_ro", [("feed", "read"), ("feed_watch", "read")])
    make_user("feeds_rw", [("feed", "read"), ("feed", "write"), ("feed_watch", "read"), ("feed_watch", "write")])
    for username, shown in (("feeds_ro", False), ("feeds_rw", True)):
        with app.test_client() as client:
            _login(client, username)
            assert (b'id="feed_form"' in client.get(url_for("feeds.feeds_page")).data) is shown
            assert (b'id="watch_form"' in client.get(url_for("feeds.watches_page")).data) is shown
            assert (b'id="replay_form"' in client.get(url_for("feeds.replay_page")).data) is shown


@pytest.mark.integration
def test_a_feed_watch_alert_shows_its_source_and_evidence(web_client, root_analysis):
    root_analysis.alert_type = ALERT_TYPE_FEED_WATCH
    root_analysis.details = {
        "feed": {"id": 1, "name": "vendor", "url": "https://vendor.example/feed", "publisher": "Vendor Advisories"},
        "entry": {"id": 1, "identity": "urn:1", "title": "Widget <b>flaw</b>", "link": "javascript:alert(1)",
                  "published_at": "2026-11-02T10:00:00", "categories": [], "text": "full text", "text_truncated": False},
        "matches": [{"watch": "exploitation", "watch_version": "v3:abcdefabcdef", "definition": "exploited",
                     "excerpt": "<script>alert(2)</script> actively exploited", "excerpt_source": "llm",
                     "rationale": "says so", "model": "gemma"}],
    }
    root_analysis.save()
    ALERT(root_analysis)

    page = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid}).data.decode()
    assert "Vendor Advisories" in page
    assert "v3:abcdefabcdef" in page
    assert "&lt;script&gt;alert(2)&lt;/script&gt; actively exploited" in page
    assert "Widget &lt;b&gt;flaw&lt;/b&gt;" in page
    # a link that is not http(s) is shown, never followed
    assert 'href="javascript:alert(1)"' not in page
    # the disposition dialog offers only a feed watch alert's dispositions
    assert 'id="option_RELEVANT"' in page and 'id="option_NOT_RELEVANT"' in page and 'id="option_IGNORE"' in page
    assert 'id="option_DELIVERY"' not in page and 'id="option_FALSE_POSITIVE"' not in page
