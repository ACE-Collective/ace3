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


def _seed_manage_session(sess, analyst_id, **overrides):
    """Seeds every session key the manage view reads, so _ensure_manage_session_defaults()
    has nothing to add and session mutation checks are meaningful.

    Filter contents live in the database now and the session only carries UUIDs, so this
    has to create a real working row: pointing filter_uuid at a row that does not exist
    would make get_effective_filters() repair the session, which is itself a write."""
    from aceapi_v2.saved_filters import service as saved_filters_service
    from aceapi_v2.saved_filters.schemas import ScratchFilterWrite
    from aceapi_v2.sync import run_async_with_session

    row = run_async_with_session(
        saved_filters_service.upsert_scratch_filter, analyst_id, 'working',
        ScratchFilterWrite(filters=overrides.get('filters', [])))

    sess['filter_uuid'] = row.uuid
    sess['filter_base_uuid'] = None
    sess['filter_state'] = 'clean'
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
        _seed_manage_session(sess, analyst, filters=[{"name": "Description", "inverted": False, "values": ["alpha"]}])

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
        _seed_manage_session(sess, analyst, page_offset=5000)
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
        _seed_manage_session(sess, analyst, checked=[alert.uuid])

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
        _seed_manage_session(sess, analyst)
        sess['search'] = 'some search query'

    response = web_client.get(url_for("analysis.manage"))
    assert response.status_code == 200
    html = response.data.decode()

    assert 'data-on-interval' not in html
    assert 'data-on:ace-refresh' not in html


@pytest.mark.integration
def test_display_disposition_hidden_when_narrowed_to_one_disposition(web_client, analyst):
    """Regression: this condition indexed the filter LIST as if it were a dict
    ('Disposition' in session['filters'] ... ['Disposition']), so it was always False and
    the column was always shown -- dead logic left over from an older filter format."""
    from app.analysis.views.manage import _ensure_manage_session_defaults, build_manage_list_context
    from app.analysis.views.session.filters import write_working_filters

    _ensure_manage_session_defaults()
    write_working_filters([{"name": "Disposition", "inverted": False, "values": ["OPEN"]}])
    assert build_manage_list_context()["display_disposition"] is False


@pytest.mark.integration
def test_display_disposition_shown_when_several_dispositions_match(web_client, analyst):
    from app.analysis.views.manage import _ensure_manage_session_defaults, build_manage_list_context
    from app.analysis.views.session.filters import write_working_filters

    _ensure_manage_session_defaults()
    write_working_filters([{"name": "Disposition", "inverted": False, "values": ["OPEN", "IGNORE"]}])
    assert build_manage_list_context()["display_disposition"] is True


@pytest.mark.integration
def test_csv_export_honors_an_active_temporary_filter(web_client, analyst):
    """The export should match the list on screen, pivot included -- otherwise an analyst
    exports something different from what they are looking at. export.py used to read the
    filter payload straight out of the session cookie."""
    import json

    _insert_alert('export-temp-filter', 'temp filter export test alert')

    # go through the client so the filter lands in the same session the export request sees
    web_client.post(url_for("analysis.apply_temp_filter"), data={
        "filters": json.dumps([{"name": "Description", "inverted": False,
                                "values": ["no-such-description-xyz"]}]),
        "label": "test"})

    response = web_client.get(url_for("analysis.export_alerts_to_csv"))
    assert response.status_code == 200
    assert 'temp filter export test alert' not in response.data.decode()


@pytest.mark.integration
def test_filter_editor_renders_a_stored_relative_token_in_relative_mode(web_client, analyst):
    """The editor picks its initial mode from the stored value, so a saved "-24h" comes back
    as an editable token rather than being clobbered by the date picker."""
    import json

    web_client.post(url_for("analysis.set_filters"), data={
        "filters": json.dumps([{"name": "Alert Date", "inverted": False, "values": ["-24h"]}])})

    body = web_client.get(url_for("analysis.manage")).data.decode()

    assert 'data-relative="1"' in body
    assert 'value="-24h"' in body
