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


def _search_response(alert_uuids, query="some search query", total=None):
    """A canned saq.search response: the first alert an exact match, the rest semantic."""
    from saq.search.types import LANE_LEXICAL, LANE_SEMANTIC, AlertSearchResult, SearchHit, SearchResponse

    results = []
    for rank, alert_uuid in enumerate(alert_uuids, start=1):
        lane = LANE_LEXICAL if rank == 1 else LANE_SEMANTIC
        results.append(AlertSearchResult(
            alert_uuid=alert_uuid, rank=rank, fused_score=1.0 / rank, tier="exact" if rank == 1 else "good",
            hits=[SearchHit(lane=lane, kind="observable" if rank == 1 else "comment", key="k", title="hit title", text="snippet text for the analyst", score=1.0)],
            lanes=frozenset({lane})))
    return SearchResponse(query=query, total=len(results) if total is None else total, offset=0, limit=50, results=results, lanes_used=frozenset({LANE_LEXICAL, LANE_SEMANTIC}))


@pytest.mark.integration
def test_manage_page_no_auto_refresh_during_search(web_client, analyst, monkeypatch):
    """The refresh POLL is disabled while a search is active -- each poll would re-run the
    search, and the results are a snapshot."""
    monkeypatch.setattr("app.analysis.views.manage.search_alerts", lambda request, **kwargs: _search_response([]))

    _insert_alert('manage-search-1', 'search suppression test alert')

    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst)
        sess['search'] = {'mode': 'query', 'query': 'some search query'}

    response = web_client.get(url_for("analysis.manage"))
    assert response.status_code == 200
    html = response.data.decode()

    assert 'data-on-interval' not in html
    # the explicit refresh (after a sort, paging or column change) stays: a user-initiated
    # change re-runs the search once, which is what the reload it replaced did
    assert 'data-on:ace-refresh' in html
    assert 'id="alert-search-clear"' in html
    assert '0 matching alerts' in html


@pytest.mark.integration
def test_manage_search_orders_by_relevance_and_shows_hits(web_client, analyst, monkeypatch):
    """The page follows the fused ranking (not the date sort), reports the fused total, and
    renders tier/kind badges without any percentage."""
    import uuid as uuidlib
    from unittest.mock import Mock

    older = _insert_alert(str(uuidlib.uuid4()), 'older but exact match')
    newer = _insert_alert(str(uuidlib.uuid4()), 'newer semantic match')
    from saq.database.pool import get_db
    get_db().execute(Alert.__table__.update().where(Alert.uuid == newer.uuid).values(insert_date='2024-01-01 00:00:00'))
    get_db().commit()

    search = Mock(return_value=_search_response([older.uuid, newer.uuid], total=7))
    monkeypatch.setattr("app.analysis.views.manage.search_alerts", search)

    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst)
        sess['search'] = {'mode': 'query', 'query': '10.20.30.40'}

    response = web_client.get(url_for("analysis.manage"))
    assert response.status_code == 200
    html = response.data.decode()

    # relevance order: the older exact match precedes the newer semantic match
    assert html.index(older.uuid) < html.index(newer.uuid)
    assert 'Exact match' in html and '>Good<' in html
    assert 'snippet text for the analyst' in html
    assert '%</span>' not in html
    assert '7 matching alerts' in html
    assert 'value="10.20.30.40"' in html

    request = search.call_args[0][0]
    assert request.query == '10.20.30.40'
    assert request.limit == 50 and request.offset == 0
    # the analyst's filters travel with the search as pre-filters and as the SQL post-filter
    assert request.filters.locations is not None
    assert callable(search.call_args.kwargs['post_filter'])


@pytest.mark.integration
def test_manage_similar_mode(web_client, analyst, monkeypatch):
    import uuid as uuidlib
    from unittest.mock import Mock

    source = _insert_alert(str(uuidlib.uuid4()), 'the source alert')
    neighbour = _insert_alert(str(uuidlib.uuid4()), 'a look-alike alert')
    similar = Mock(return_value=_search_response([neighbour.uuid], query=f"similar:{source.uuid}"))
    monkeypatch.setattr("app.analysis.views.manage.similar_alerts", similar)

    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst)

    response = web_client.get(url_for("analysis.search_similar", alert_uuid=source.uuid))
    assert response.status_code == 302

    response = web_client.get(url_for("analysis.manage"))
    assert response.status_code == 200
    html = response.data.decode()
    assert 'value="Similar to: the source alert"' in html
    assert 'readonly' in html
    assert neighbour.uuid in html
    assert similar.call_args[0][0] == source.uuid


@pytest.mark.integration
def test_search_endpoint_sets_and_clears_the_spec(web_client, analyst):
    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst, page_offset=100)

    assert web_client.post(url_for("analysis.search"), data={"search": "  invoice  "}).status_code == 204
    with web_client.session_transaction() as sess:
        assert sess['search'] == {'mode': 'query', 'query': 'invoice'}
        assert sess['page_offset'] == 0

    assert web_client.post(url_for("analysis.search"), data={"search": ""}).status_code == 204
    with web_client.session_transaction() as sess:
        assert sess['search'] is None


@pytest.mark.integration
def test_search_endpoint_requires_alert_read(app):
    from saq.database.util.user_management import add_user, delete_user

    add_user(username="noperm", email="noperm@localhost", display_name="noperm", password="password")
    try:
        with app.test_client() as client:
            client.post(url_for("auth.login"), data={"username": "noperm", "password": "password"})
            assert client.post(url_for("analysis.search"), data={"search": "x"}).status_code == 403
            assert client.get(url_for("analysis.search_similar", alert_uuid="x")).status_code == 403
    finally:
        delete_user("noperm")


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


@pytest.mark.integration
def test_manage_search_repages_when_offset_is_past_the_end(web_client, analyst, monkeypatch):
    """A remembered page offset beyond the (now smaller) result set is clamped and the search
    re-run with the clamped offset, so the analyst never sees an empty page with a total."""
    import uuid as uuidlib
    from unittest.mock import Mock

    only = _insert_alert(str(uuidlib.uuid4()), 'the only match')

    def fake_search(request, **kwargs):
        response = _search_response([only.uuid])
        response.offset = request.offset
        response.results = response.results if request.offset == 0 else []
        return response

    search = Mock(side_effect=fake_search)
    monkeypatch.setattr("app.analysis.views.manage.search_alerts", search)

    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst, page_offset=100)
        sess['search'] = {'mode': 'query', 'query': 'match'}

    response = web_client.get(url_for("analysis.manage"))
    assert response.status_code == 200
    assert only.uuid in response.data.decode()
    assert [call[0][0].offset for call in search.call_args_list] == [100, 0]


# --- column layout -----------------------------------------------------------------------

def _set_manage_columns(analyst_id, **value):
    """Store the analyst's column layout the way the API would."""
    from aceapi_v2.sync import run_async_with_session
    from aceapi_v2.user_preferences import service
    from aceapi_v2.user_preferences.schemas import PREFERENCE_KEY_MANAGE_COLUMNS

    run_async_with_session(service.set_preference, analyst_id, PREFERENCE_KEY_MANAGE_COLUMNS, value)


def _header_columns(html: str) -> list[str]:
    import re
    return re.findall(r'<th[^>]*data-col-id="([a-z_]+)"', html)


def _row_columns(html: str, alert_uuid: str) -> list[str]:
    import re
    row = re.search(rf'<tr id="alert_row_{alert_uuid}".*?</tr>', html, re.S).group(0)
    return re.findall(r'<td[^>]*data-col-id="([a-z_]+)"', row)


@pytest.mark.integration
def test_manage_table_default_columns(web_client, analyst):
    from saq.gui.manage_columns import MANAGE_COLUMN_IDS

    alert = _insert_alert('manage-columns-default', 'default columns test alert')
    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst)

    html = web_client.get(url_for("analysis.manage_refresh")).data.decode()
    assert _header_columns(html) == list(MANAGE_COLUMN_IDS)
    assert _row_columns(html, alert.uuid) == list(MANAGE_COLUMN_IDS)
    # the labels the registry declares are what the header shows
    for label in ("Date (", "Alert", "Remediation", "Queue", "Owner", "Disposition", "Status"):
        assert label in html


@pytest.mark.integration
def test_manage_table_follows_the_column_preference(web_client, analyst):
    """Hidden columns are absent from header AND rows, the order is the analyst's, and the
    row data JavaScript needs no longer depends on a column being shown."""
    alert = _insert_alert('manage-columns-pref', 'column preference test alert')
    _set_manage_columns(analyst,
        order=["status", "description", "date", "queue", "owner", "disposition", "remediation"],
        hidden=["queue", "owner", "date"])
    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst)

    html = web_client.get(url_for("analysis.manage_refresh")).data.decode()
    expected = ["status", "description", "disposition", "remediation"]
    assert _header_columns(html) == expected
    assert _row_columns(html, alert.uuid) == expected
    assert f'id="alert_row_{alert.uuid}" data-status="' in html
    assert 'data-insert-date="2023-01-01 00:00:00"' in html


@pytest.mark.integration
def test_manage_table_disposition_override_keeps_header_and_rows_aligned(web_client, analyst):
    """Narrowing to one disposition drops the column from the rows too (it used to drop only
    the header, leaving every row one cell wider than the header)."""
    alert = _insert_alert('manage-columns-dispo', 'disposition override test alert')
    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst, filters=[{"name": "Disposition", "inverted": False, "values": ["OPEN"]}])

    html = web_client.get(url_for("analysis.manage_refresh")).data.decode()
    assert "disposition" not in _header_columns(html)
    assert _header_columns(html) == _row_columns(html, alert.uuid)


@pytest.mark.integration
def test_manage_search_hits_span_the_visible_columns(web_client, analyst, monkeypatch):
    _insert_alert('manage-columns-search', 'search colspan test alert')
    monkeypatch.setattr("app.analysis.views.manage.search_alerts",
                        lambda request, **kwargs: _search_response(['manage-columns-search']))
    _set_manage_columns(analyst, hidden=["queue", "owner"])
    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst)
        sess['search'] = {'mode': 'query', 'query': 'colspan'}

    html = web_client.get(url_for("analysis.manage_refresh")).data.decode()
    assert len(_header_columns(html)) == 5
    assert '<td colspan="5">' in html


@pytest.mark.integration
def test_manage_page_renders_the_column_chooser(web_client, analyst):
    _set_manage_columns(analyst, hidden=["queue"])
    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst)

    html = web_client.get(url_for("analysis.manage")).data.decode()
    assert 'id="manage_columns_dropdown"' in html
    assert 'data-preference-url="/api/v2/users/me/preferences/manage_columns"' in html
    assert 'js/manage_columns.js' in html
    # the chooser reflects the stored layout: queue unticked, description locked on
    assert 'id="column_chooser_queue"\n' in html or 'id="column_chooser_queue"' in html
    import re
    queue_input = re.search(r'<input[^>]*id="column_chooser_queue"[^>]*>', html).group(0)
    assert 'checked' not in queue_input
    description_input = re.search(r'<input[^>]*id="column_chooser_description"[^>]*>', html).group(0)
    assert 'checked' in description_input and 'disabled' in description_input
    # the chooser is outside the morph fragments
    assert 'column-chooser' not in web_client.get(url_for("analysis.manage_refresh")).data.decode()
