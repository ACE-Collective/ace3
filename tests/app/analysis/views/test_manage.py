import pytest
from flask import url_for

from saq.constants import DISPOSITION_OPEN, QUEUE_DEFAULT
from saq.database.model import Alert
from saq.database.util.alert import ALERT


@pytest.mark.integration
def test_manage(web_client, root_analysis):
    root_analysis.save() # TODO ALERT should save()
    alert = ALERT(root_analysis)
    assert isinstance(alert, Alert)

    result = web_client.get(url_for("analysis.manage"))
    assert result.status_code == 200


def _insert_alert(uuid, description):
    """Inserts a minimal alert on the local node that matches the default (Reset) filters:
    open, unowned, in the default queue."""
    from saq.database.pool import get_db
    from saq.environment import get_global_runtime_settings
    from saq.gui.alert import GUIAlert

    db = get_db()
    alert = GUIAlert()
    alert.uuid = uuid
    alert.storage_dir = f'/tmp/{uuid}'
    alert.tool = 'test'
    alert.tool_instance = 'test'
    alert.alert_type = 'test'
    alert.description = description
    alert.priority = 1
    alert.disposition = DISPOSITION_OPEN
    alert.owner_id = None
    alert.queue = QUEUE_DEFAULT
    alert.location = get_global_runtime_settings().saq_node
    alert.insert_date = '2023-01-01 00:00:00'
    db.add(alert)
    db.commit()
    return alert


def _seed_manage_session(sess, **overrides):
    """Seeds every session key the manage view reads, so _ensure_manage_session_defaults()
    has nothing to add and session mutation checks are meaningful."""
    sess['filters'] = overrides.get('filters', [])
    sess['checked'] = overrides.get('checked', [])
    sess['page_offset'] = overrides.get('page_offset', 0)
    sess['page_size'] = overrides.get('page_size', 50)
    sess['sort_filter'] = overrides.get('sort_filter', 'Alert Date')
    sess['sort_filter_desc'] = overrides.get('sort_filter_desc', True)


@pytest.mark.integration
def test_manage_refresh_returns_fragments(web_client, analyst):
    """The refresh endpoint returns the two morph fragments as a plain HTML fragment
    with the per-user cache policy."""
    _insert_alert('manage-refresh-1', 'refresh endpoint test alert')

    response = web_client.get(url_for("analysis.manage_refresh"))
    assert response.status_code == 200
    # per-user data must never be handed to a shared/proxy cache
    assert response.headers.get('Cache-Control') == 'private, no-store'

    html = response.data.decode()
    assert 'id="manage_filter_bar"' in html
    assert 'id="manage_alert_table"' in html
    assert 'alert_row_manage-refresh-1' in html
    # a fragment, not a page
    assert '<html' not in html
    # the polling attribute lives on the non-morphed wrapper in manage.html -- if it
    # ever appears in the patched markup, every poll re-arms it and storms the server
    assert 'data-on-interval' not in html


@pytest.mark.integration
def test_manage_refresh_honors_session_filters(web_client, analyst):
    """The refresh endpoint renders the alert list through the same session filters as
    the manage page."""
    _insert_alert('manage-refresh-match', 'alpha searchable alert')
    _insert_alert('manage-refresh-nomatch', 'beta other alert')

    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, filters=[{"name": "Description", "inverted": False, "values": ["alpha"]}])

    response = web_client.get(url_for("analysis.manage_refresh"))
    assert response.status_code == 200

    html = response.data.decode()
    assert 'alert_row_manage-refresh-match' in html
    assert 'alert_row_manage-refresh-nomatch' not in html


@pytest.mark.integration
def test_manage_refresh_does_not_mutate_session(web_client, analyst):
    """The polled endpoint must never write the session: a poll response's Set-Cookie
    could race a user-initiated request and clobber its session changes. The page offset
    is clamped into a local for rendering instead."""
    _insert_alert('manage-refresh-clamp', 'page offset clamp test alert')

    with web_client.session_transaction() as sess:
        # an offset far past the total exercises the render-time clamp
        _seed_manage_session(sess, page_offset=5000)
        before = dict(sess)

    response = web_client.get(url_for("analysis.manage_refresh"))
    assert response.status_code == 200
    # the clamped offset renders the last page even though the session still says 5000
    assert 'alert_row_manage-refresh-clamp' in response.data.decode()

    with web_client.session_transaction() as sess:
        assert dict(sess) == before
        assert sess['page_offset'] == 5000


@pytest.mark.integration
def test_manage_refresh_requires_login(app):
    """Unauthenticated browsers get the login redirect; unauthenticated Datastar polls
    get a 401 instead, so the poller never receives a login page to morph in."""
    with app.test_client() as client:
        response = client.get(url_for("analysis.manage_refresh"), follow_redirects=False)
        assert response.status_code == 302

        response = client.get(url_for("analysis.manage_refresh"), headers={"Datastar-Request": "true"}, follow_redirects=False)
        assert response.status_code == 401


@pytest.mark.integration
def test_manage_page_wires_datastar(web_client, analyst):
    """The manage page loads the Datastar bundle, declares the signals on the
    non-morphed wrapper, arms the poll, and binds the row checkboxes to $_sel."""
    alert = _insert_alert('manage-datastar-1', 'datastar wiring test alert')

    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, checked=[alert.uuid])

    response = web_client.get(url_for("analysis.manage"))
    assert response.status_code == 200
    html = response.data.decode()

    assert 'js/datastar-1.0.2.js' in html
    # default gui.manage_auto_refresh_seconds is 30
    assert 'data-on-interval__duration.30s' in html
    # the favicon notification-dot poll follows the same cadence
    assert 'data-poll-seconds="30"' in html
    # $_sel is seeded from session['checked'] so post-bulk-action restores go through the signal
    assert f'data-signals:_sel=\'["{alert.uuid}"]\'' in html
    # checked state comes from data-bind against the signal, not a server-rendered attribute
    assert 'data-bind:_sel' in html
    assert f'value="{alert.uuid}"' in html
    assert f'id="cb_{alert.uuid}"' in html


@pytest.mark.integration
def test_manage_page_no_auto_refresh_during_search(web_client, analyst, monkeypatch):
    """Auto-refresh is disabled while a vector search is active -- each refresh would
    re-run the embedding search, and the results are a snapshot."""
    monkeypatch.setattr("saq.llm.embedding.search.search", lambda query: [])

    _insert_alert('manage-search-1', 'search suppression test alert')

    with web_client.session_transaction() as sess:
        _seed_manage_session(sess)
        sess['search'] = 'some search query'

    response = web_client.get(url_for("analysis.manage"))
    assert response.status_code == 200
    html = response.data.decode()

    assert 'data-on-interval' not in html
    assert 'data-on:ace-refresh' not in html
