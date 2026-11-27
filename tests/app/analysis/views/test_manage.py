import html as html_lib
import json
import re
from types import SimpleNamespace

import pytest
from flask import url_for

from aceapi_v2.saved_filters import service as saved_filters_service
from aceapi_v2.saved_filters.schemas import SavedFilterCreate
from aceapi_v2.sync import run_async_with_session
from saq.configuration.config import get_config
from saq.configuration.schema import ExternalRemediationProbeConfig, RemediatorConfig
from saq.constants import DISPOSITION_OPEN, F_EMAIL_DELIVERY, QUEUE_DEFAULT
from saq.database.model import Alert
from saq.database.pool import get_db
from saq.gui import filter_query
from tests.saq.helpers import attach_observable, insert_alert_with_email_targets


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
        ScratchFilterWrite(filters=overrides.get('filters', [])), screen='alerts')

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
    non-morphed wrapper, arms the poll, and ties the row checkboxes to $_sel by uuid."""
    alert = _insert_alert('manage-datastar-1', 'datastar wiring test alert')

    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst, checked=[alert.uuid])

    response = web_client.get(url_for("analysis.manage"))
    assert response.status_code == 200
    html = response.data.decode()

    assert 'js/datastar-1.0.4.js' in html
    # default gui.manage_auto_refresh_seconds is 30
    assert 'data-on-interval__duration.30s' in html
    # the favicon notification-dot poll follows the same cadence
    assert 'data-poll-seconds="30"' in html
    # $_sel is seeded from session['checked'] so post-bulk-action restores go through the signal
    assert f'data-signals:_sel=\'["{alert.uuid}"]\'' in html
    # checked state comes from the row's uuid being in the signal, not a server-rendered
    # attribute -- and not data-bind, which ties each checkbox to an array position that a
    # row inserted by a refresh collides with
    assert 'data-effect="el.checked = $_sel.includes(el.value)"' in html
    assert 'data-bind:_sel' not in html
    assert f'value="{alert.uuid}"' in html
    assert f'id="cb_{alert.uuid}"' in html


@pytest.mark.integration
def test_manage_page_favicon_polls_the_reset_filter_count(web_client, analyst):
    """The tab's notification dot counts the "Reset" filter through GET /api/v2/alerts/count, so
    the URL it polls carries exactly that filter for the logged-in analyst."""
    from urllib.parse import parse_qs, urlsplit
    from saq.gui.filter_url import decode_filter_query

    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst)

    html = web_client.get(url_for("analysis.manage")).data.decode()
    url = html_lib.unescape(re.search(r'data-reset-filter-count-url="([^"]*)"', html).group(1))

    parts = urlsplit(url)
    assert parts.path == "/api/v2/alerts/count"
    filters, warnings = decode_filter_query(parse_qs(parts.query)["f"], strict=True)
    assert warnings == []
    assert [(f["name"], f["inverted"], f["values"]) for f in filters] == [
        ("Disposition", False, [DISPOSITION_OPEN]),
        ("Owner", False, ["None", "john"]),
        ("Queue", False, [QUEUE_DEFAULT]),
    ]


@pytest.mark.integration
def test_other_pages_do_not_poll_the_reset_filter_count(web_client, analyst):
    html = web_client.get(url_for("events.manage")).data.decode()
    assert "data-reset-filter-count-url" not in html


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
def test_manage_search_drops_matches_the_filters_exclude(web_client, analyst, monkeypatch):
    """The view's SQL post-filter keeps only the search matches the analyst's filters let through."""
    import uuid as uuidlib

    kept = _insert_alert(str(uuidlib.uuid4()), 'alpha alert')
    filtered_out = _insert_alert(str(uuidlib.uuid4()), 'beta alert')

    def search(request, post_filter):
        return _search_response(post_filter([filtered_out.uuid, kept.uuid, str(uuidlib.uuid4())]))

    monkeypatch.setattr("app.analysis.views.manage.search_alerts", search)

    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst, filters=[{"name": "Description", "inverted": False, "values": ["alpha"]}])
        sess['search'] = {'mode': 'query', 'query': 'alert'}

    response = web_client.get(url_for("analysis.manage"))
    assert response.status_code == 200
    html = response.data.decode()
    assert kept.uuid in html
    assert filtered_out.uuid not in html
    assert '1 matching alert,' in html


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
def test_the_test_alert_toggle(web_client, analyst):
    """docs/SVS_RUNS.md: the analyst can bring back the test-run alerts a search left out."""
    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst, page_offset=100)
        sess['search'] = {'mode': 'query', 'query': 'invoice'}

    url = url_for("analysis.search_include_tests")
    assert web_client.post(url, data={"include": "1"}).status_code == 204
    with web_client.session_transaction() as sess:
        assert sess['search'] == {'mode': 'query', 'query': 'invoice', 'include_tests': True}
        assert sess['page_offset'] == 0

    assert web_client.post(url, data={"include": "0"}).status_code == 204
    with web_client.session_transaction() as sess:
        assert sess['search'] == {'mode': 'query', 'query': 'invoice'}

    # a new search starts without it
    web_client.post(url, data={"include": "1"})
    web_client.post(url_for("analysis.search"), data={"search": "other"})
    with web_client.session_transaction() as sess:
        assert sess['search'] == {'mode': 'query', 'query': 'other'}


@pytest.mark.integration
def test_the_test_alert_toggle_without_a_search(web_client, analyst):
    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst)

    assert web_client.post(url_for("analysis.search_include_tests"), data={"include": "1"}).status_code == 204
    with web_client.session_transaction() as sess:
        assert not sess.get('search')


@pytest.mark.integration
@pytest.mark.parametrize("include_tests,excluded,expected", [
    (False, 3, ["3 test-run alerts left out.", 'data-include="1"', "Include them"]),
    (False, 1, ["1 test-run alert left out."]),
    (True, None, ["Test-run alerts are included.", 'data-include="0"', "Leave them out"]),
])
def test_manage_search_says_what_it_left_out(web_client, analyst, monkeypatch, include_tests, excluded, expected):
    from unittest.mock import Mock

    response = _search_response([])
    response.excluded_test_alerts = excluded
    search = Mock(return_value=response)
    monkeypatch.setattr("app.analysis.views.manage.search_alerts", search)

    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst)
        sess['search'] = {'mode': 'query', 'query': 'mimikatz', **({'include_tests': True} if include_tests else {})}

    html = web_client.get(url_for("analysis.manage")).data.decode()
    for text in expected:
        assert text in html
    assert search.call_args[0][0].include_test_alerts is include_tests


@pytest.mark.integration
@pytest.mark.parametrize("excluded", [0, None])
def test_manage_search_says_nothing_when_nothing_was_left_out(web_client, analyst, monkeypatch, excluded):
    response = _search_response([])
    response.excluded_test_alerts = excluded
    monkeypatch.setattr("app.analysis.views.manage.search_alerts", lambda request, **kwargs: response)

    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst)
        sess['search'] = {'mode': 'query', 'query': 'mimikatz'}

    assert 'id="alert-search-tests"' not in web_client.get(url_for("analysis.manage")).data.decode()


@pytest.mark.integration
def test_similar_mode_passes_include_tests(web_client, analyst, monkeypatch):
    from unittest.mock import Mock

    similar = Mock(return_value=_search_response([]))
    monkeypatch.setattr("app.analysis.views.manage.similar_alerts", similar)

    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst)
        sess['search'] = {'mode': 'similar', 'alert_uuid': 'x', 'description': 'd', 'include_tests': True}

    web_client.get(url_for("analysis.manage"))
    assert similar.call_args.kwargs['include_test_alerts'] is True


@pytest.mark.integration
def test_search_endpoint_requires_alert_read(app):
    from saq.database.util.user_management import add_user, delete_user

    add_user(username="noperm", email="noperm@localhost", display_name="noperm", password="password")
    try:
        with app.test_client() as client:
            client.post(url_for("auth.login"), data={"username": "noperm", "password": "password"})
            assert client.post(url_for("analysis.search"), data={"search": "x"}).status_code == 403
            assert client.get(url_for("analysis.search_similar", alert_uuid="x")).status_code == 403
            assert client.post(url_for("analysis.search_include_tests"), data={"include": "1"}).status_code == 403
    finally:
        delete_user("noperm")


def _export_url(html: str):
    """The CSV export URL the filter bar carries, split into its path and query."""
    from urllib.parse import parse_qs, urlsplit

    url = html_lib.unescape(re.search(r'data-export-url="([^"]*)"', html).group(1))
    parts = urlsplit(url)
    return parts.path, parse_qs(parts.query)


@pytest.mark.integration
def test_csv_export_exports_the_filter_on_screen(web_client, analyst):
    """Export to CSV downloads GET /api/v2/alerts/export/csv with the filters the bar shows, a
    temporary pivot included -- otherwise an analyst exports something different from what
    they are looking at -- and the analyst's timezone for relative dates."""
    import json
    from saq.gui.filter_url import decode_filter_query

    pivot = [{"name": "Description", "inverted": False, "values": ["no-such-description-xyz"]}]
    web_client.post(url_for("analysis.apply_temp_filter"), data={"filters": json.dumps(pivot), "label": "test"})

    html = web_client.get(url_for("analysis.manage")).data.decode()
    assert 'onclick="export_alerts_to_csv()"' in html

    path, query = _export_url(html)
    assert path == "/api/v2/alerts/export/csv"
    assert query["tz"] == ["UTC"]
    assert decode_filter_query(query["f"], strict=True) == (pivot, [])


@pytest.mark.integration
def test_csv_export_url_follows_the_refreshed_filter_bar(web_client, analyst):
    """The filter bar is what the refresh poll re-renders, so the URL rides on it rather than on
    the action bar, which is rendered once."""
    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst, filters=[{"name": "Queue", "inverted": False, "values": ["external"]}])

    refresh = web_client.get(url_for("analysis.manage_refresh")).data.decode()

    path, query = _export_url(refresh)
    assert path == "/api/v2/alerts/export/csv"
    assert query["f"] == ["queue:external"]


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
def test_analysis_filter_on_the_manage_page(web_client, analyst):
    """The list shows only the alerts containing the analysis type, the filter bar names the
    type by its display name rather than its module path, and the editor offers it selected."""
    from saq.database.model import AnalysisMapping, AnalysisType

    module_path = "saq.modules.file_analysis.qrcode:QRCodeAnalysis"
    _insert_alert('manage-analysis-match', 'has a qr code')
    _insert_alert('manage-analysis-nomatch', 'has no qr code')
    db = get_db()
    analysis_type = AnalysisType(module_path=module_path, display_name="QR Code Analysis")
    db.add(analysis_type)
    db.flush()
    match = db.query(Alert).filter(Alert.uuid == 'manage-analysis-match').one()
    db.add(AnalysisMapping(alert_id=match.id, analysis_type_id=analysis_type.id))
    db.commit()

    response = web_client.post(url_for("analysis.set_filters"), data={
        "filters": json.dumps([{"name": "Analysis", "inverted": False, "values": [module_path]}])})
    assert response.status_code == 204

    body = web_client.get(url_for("analysis.manage")).data.decode()

    assert 'alert_row_manage-analysis-match' in body
    assert 'alert_row_manage-analysis-nomatch' not in body
    assert '>QR Code Analysis</span>' in body
    assert f'>{module_path}</span>' not in body
    assert re.search(rf'<option value="{re.escape(module_path)}"[^>]*SELECTED[^>]*>QR Code Analysis</option>', body)


@pytest.mark.integration
def test_remediation_filter_on_the_manage_page(web_client, analyst):
    """The list shows the alerts the stored [source, state] pairs match; the editor offers Any and
    the email remediators and probes configured, the remediator by its display name, and shows
    each stored row selected, a source that is no longer configured included."""
    config = get_config()
    for name, observable_type in (("email_remediator", F_EMAIL_DELIVERY), ("url_remediator", "url")):
        config.add_remediator_config(name, RemediatorConfig(
            name=name, display_name=f"{name} display", description="unused", observable_type=observable_type,
            python_module="unused", python_class="Unused"))
    config.add_external_remediation_probe_config("email_probe", ExternalRemediationProbeConfig(
        name="email_probe", observable_type=F_EMAIL_DELIVERY, python_module="unused", python_class="Unused"))

    def watched_by(probe: str):
        target = f"<m@x>|{probe}@example.com"
        return insert_alert_with_email_targets((target,), checks=[SimpleNamespace(
            observable_value=target, status="NEW", result=None, probe_name=probe, result_message=None,
            events_json=None)])

    watched = watched_by("email_probe")
    watched_by_another = watched_by("another_probe")

    stored = [["email_probe", "watching"], ["retired_probe", "failed"]]
    response = web_client.post(url_for("analysis.set_filters"), data={
        "filters": json.dumps([{"name": "Remediation", "inverted": False, "values": stored}])})
    assert response.status_code == 204

    body = web_client.get(url_for("analysis.manage")).data.decode()

    assert f'alert_row_{watched.uuid}' in body
    assert f'alert_row_{watched_by_another.uuid}' not in body

    rows = re.findall(r'display:block" name="[^"]+" id="filter_[^"]+_value_container_Remediation">'
                      r'(.*?</select>.*?</select>)', body, re.DOTALL)
    selected = [re.findall(r'<option value="([^"]*)"[^>]*SELECTED[^>]*>', row) for row in rows]
    assert selected == stored

    offered = dict(re.findall(r'<option value="([^"]*)"[^>]*>([^<]*)</option>', rows[0].split("</select>")[0]))
    assert offered == {"Any": "Any", "email_remediator": "email_remediator display", "email_probe": "email_probe"}


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
    assert f'id="alert_row_{alert.uuid}" data-queue="{QUEUE_DEFAULT}"' in html
    assert 'data-owner-id=""' in html


@pytest.mark.integration
def test_manage_table_shows_disposition_when_filtered_to_one_disposition(web_client, analyst):
    """A disposition filter never hides the disposition column: without it, a list narrowed
    to one disposition reads as a list of alerts that were never dispositioned."""
    alert = _insert_alert('manage-columns-dispo', 'disposition filter test alert')
    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst, filters=[{"name": "Disposition", "inverted": False, "values": ["OPEN"]}])

    html = web_client.get(url_for("analysis.manage_refresh")).data.decode()
    assert "disposition" in _header_columns(html)
    assert _header_columns(html) == _row_columns(html, alert.uuid)


@pytest.mark.integration
def test_manage_table_disposition_column_follows_the_preference_under_a_disposition_filter(web_client, analyst):
    alert = _insert_alert('manage-columns-dispo-hidden', 'hidden disposition filter test alert')
    _set_manage_columns(analyst, hidden=["disposition"])
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


@pytest.mark.integration
def test_manage_page_renders_the_commonalities_panel(web_client, analyst):
    """The Commonalities toggle and panel sit outside the polled fragments, a group's checkbox can
    add to the selection signal, and each row carries the description the panel labels it with."""
    _insert_alert('commonalities-row', 'payload <b>"one"</b> & more')

    html = web_client.get(url_for("analysis.manage")).data.decode()
    assert 'id="btn-commonalities"' in html
    panel = re.search(r'<div id="commonality_panel"[^>]*>', html).group(0)
    assert 'hidden' in panel
    assert f'data-apply-url="{url_for("analysis.apply_temp_filter")}"' in panel
    assert 'js/manage_commonalities.js' in html
    assert 'data-on:ace-select=' in html
    row = re.search(r'<tr id="alert_row_commonalities-row"[^>]*>', html).group(0)
    assert 'data-description="payload &lt;b&gt;&#34;one&#34;&lt;/b&gt; &amp; more"' in row

    refreshed = web_client.get(url_for("analysis.manage_refresh")).data.decode()
    assert 'commonality_panel' not in refreshed and 'btn-commonalities' not in refreshed
    assert 'data-description="payload' in refreshed


@pytest.mark.integration
def test_manage_flags_a_page_that_mixes_queues(web_client, analyst):
    """Select-all takes the whole page, so a page with more than one queue says so and
    offers to select one queue's alerts; the rows carry what the bulk-action dialogs read."""
    _insert_alert('queue-mix-default', 'queue mix default alert')
    tuning = _insert_alert('queue-mix-tuning', 'queue mix tuning alert')
    tuning.queue = 'tuning'
    tuning.owner_id = analyst
    get_db().commit()

    web_client.post(url_for("analysis.apply_temp_filter"), data={
        "filters": json.dumps([{"name": "Description", "inverted": False, "values": ["queue mix"]}]),
        "label": "test"})

    html = web_client.get(url_for("analysis.manage")).data.decode()
    assert 'id="manage_queue_mix"' in html
    assert 'data-uuids=\'["queue-mix-tuning"]\'' in html

    row = re.search(r'<tr id="alert_row_queue-mix-tuning"[^>]*>', html).group(0)
    assert 'data-queue="tuning"' in row
    assert f'data-owner-id="{analyst}"' in row
    assert 'data-owner-enabled="1"' in row


@pytest.mark.integration
def test_manage_does_not_flag_a_single_queue_page(web_client, analyst):
    _insert_alert('queue-single', 'single queue alert')

    html = web_client.get(url_for("analysis.manage")).data.decode()
    assert 'alert_row_queue-single' in html
    assert 'id="manage_queue_mix"' not in html


@pytest.mark.integration
def test_manage_page_uses_the_saved_filter_component(web_client, analyst):
    """Saved filters are saved, deleted and ordered through /api/v2/saved-filters by
    static/js/saved_filters.js; the page renders its dialogs once, outside the morph fragments."""
    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst)

    html = web_client.get(url_for("analysis.manage")).data.decode()
    for script in ("js/ace_api.js", "js/saved_filters.js", "js/manage_alerts.js"):
        assert script in html
    assert html.index("js/saved_filters.js") < html.index("js/manage_alerts.js")
    assert html.count('id="save_filter_modal"') == 1
    assert html.count('id="manage_filters_modal"') == 1
    assert 'onsubmit="return SAVED_FILTERS.saveAs();"' in html
    assert 'id="save_filter_indicator"' in html
    assert 'onmousedown="SAVED_FILTERS.openManage()"' in html
    assert "init_saved_filters(" in html

    # "Save a copy" saves what the bar shows, so the bar carries the filter list in effect
    refresh = web_client.get(url_for("analysis.manage_refresh")).data.decode()
    for page in (html, refresh):
        carried = re.search(r"data-effective-filters='([^']*)'", page).group(1)
        assert isinstance(json.loads(html_lib.unescape(carried)), list)
    assert 'id="save_filter_modal"' not in refresh


@pytest.mark.unit
def test_the_flask_saved_filter_routes_are_gone(app):
    endpoints = {rule.endpoint for rule in app.url_map.iter_rules()}
    for removed in ("create_saved_filter", "update_saved_filter", "delete_saved_filter",
                    "set_quick_filters", "saved_filter_link", "saved_filters_modal_body"):
        assert f"analysis.{removed}" not in endpoints
    assert "analysis.select_filter" in endpoints


PATTERN_FILTER = [{"name": "Observable Pattern", "inverted": False, "values": [["fqdn", "*.evil.com"]]}]


@pytest.mark.integration
def test_observable_pattern_filter_on_the_manage_page(web_client, analyst):
    """The list shows the alerts the pattern matches, the bar shows the pattern, and the editor
    offers it in a type and value pair like the exact Observable filter."""
    attach_observable(_insert_alert('manage-pattern-match', 'evil subdomain'), "fqdn", "mail.evil.com")
    attach_observable(_insert_alert('manage-pattern-nomatch', 'lookalike'), "fqdn", "evil.com.attacker.net")

    response = web_client.post(url_for("analysis.set_filters"), data={"filters": json.dumps(PATTERN_FILTER)})
    assert response.status_code == 204

    body = web_client.get(url_for("analysis.manage")).data.decode()
    assert 'alert_row_manage-pattern-match' in body
    assert 'alert_row_manage-pattern-nomatch' not in body
    assert '>fqdn:*.evil.com</span>' in body
    assert 'placeholder="*.evil.com or https://evil.com/*"' in body
    assert 'value="*.evil.com"' in body


@pytest.mark.integration
def test_a_pattern_with_a_wildcard_at_both_ends_is_refused_when_applied(web_client, analyst):
    for route in ("analysis.set_filters", "analysis.apply_temp_filter"):
        response = web_client.post(url_for(route), data={"filters": json.dumps(
            [{"name": "Observable Pattern", "inverted": False, "values": [["fqdn", "*evil*"]]}])})
        assert response.status_code == 400
        assert "both ends" in response.data.decode()


@pytest.mark.integration
@pytest.mark.parametrize("route", ["analysis.manage", "analysis.manage_refresh"])
def test_a_pattern_that_cannot_be_run_lists_nothing_and_says_why(web_client, analyst, monkeypatch, route):
    """Listing the alerts without the filter would show more than the analyst asked for."""
    attach_observable(_insert_alert('manage-pattern-toomany', 'evil subdomain'), "fqdn", "mail.evil.com")
    _insert_alert('manage-pattern-other', 'no observables')
    monkeypatch.setattr(filter_query, "MAX_PATTERN_OBSERVABLES", 0)

    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst, filters=PATTERN_FILTER)

    response = web_client.get(url_for(route))
    assert response.status_code == 200
    html = response.data.decode()
    assert 'alert_row_manage-pattern-toomany' not in html
    assert 'alert_row_manage-pattern-other' not in html
    assert 'matches more than 0 observables; make it more specific' in html_lib.unescape(html)


@pytest.mark.integration
def test_a_pattern_that_cannot_be_run_skips_the_search(web_client, analyst, monkeypatch):
    def search(*args, **kwargs):
        raise AssertionError("the search ran")

    monkeypatch.setattr("app.analysis.views.manage.search_alerts", search)
    attach_observable(_insert_alert('manage-pattern-search', 'evil subdomain'), "fqdn", "mail.evil.com")
    monkeypatch.setattr(filter_query, "MAX_PATTERN_OBSERVABLES", 0)

    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst, filters=PATTERN_FILTER)
        sess['search'] = {'mode': 'query', 'query': 'evil'}

    html = html_lib.unescape(web_client.get(url_for("analysis.manage")).data.decode())
    assert 'matches more than 0 observables' in html
    assert '0 matching alerts' in html
    assert 'alert_row_manage-pattern-search' not in html


@pytest.mark.integration
def test_a_badge_whose_pattern_cannot_be_run_says_why(web_client, analyst, monkeypatch):
    """The badge count runs on every page render, so it must not take the page down; and a badge
    that can no longer be counted must not look like one with no alerts, or the analyst watching
    an indicator through it stops hearing about it."""
    attach_observable(_insert_alert('manage-pattern-badge', 'evil subdomain'), "fqdn", "mail.evil.com")
    run_async_with_session(
        saved_filters_service.create_saved_filter, analyst,
        SavedFilterCreate(name="evil subdomains", filters=PATTERN_FILTER, quick_filter=True,
                          quick_filter_indicator=True),
        screen='alerts')

    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst)

    dot = 'title="1 evil subdomains alert(s)"'
    assert dot in web_client.get(url_for("analysis.manage")).data.decode()

    monkeypatch.setattr(filter_query, "MAX_PATTERN_OBSERVABLES", 0)
    response = web_client.get(url_for("analysis.manage"))
    assert response.status_code == 200
    html = html_lib.unescape(response.data.decode())
    assert 'evil subdomains' in html and dot not in html
    warning = re.search(r'<span class="quick-filter-error[^"]*" title="([^"]*)"', html)
    assert warning is not None
    assert 'matches more than 0 observables; make it more specific' in warning.group(1)


@pytest.mark.integration
def test_a_search_looks_a_pattern_up_once(web_client, analyst, monkeypatch):
    """The search calls post_filter once per batch of candidates it fuses; each call used to
    build the filters again, and look the pattern's observables up again."""
    match = _insert_alert('manage-pattern-search-match', 'evil subdomain')
    attach_observable(match, "fqdn", "mail.evil.com")
    other = _insert_alert('manage-pattern-search-other', 'lookalike')
    attach_observable(other, "fqdn", "evil.com.attacker.net")

    lookups = []
    resolve = filter_query.resolve_observable_pattern
    monkeypatch.setattr(filter_query, "resolve_observable_pattern",
                        lambda *args: lookups.append(args) or resolve(*args))

    def search(request, post_filter):
        for _ in range(3):
            kept = post_filter([match.uuid, other.uuid])
        return _search_response(kept)

    monkeypatch.setattr("app.analysis.views.manage.search_alerts", search)
    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst, filters=PATTERN_FILTER)
        sess['search'] = {'mode': 'query', 'query': 'evil'}

    html = web_client.get(url_for("analysis.manage")).data.decode()
    assert 'alert_row_manage-pattern-search-match' in html
    assert 'alert_row_manage-pattern-search-other' not in html
    assert lookups == [("fqdn", "*.evil.com")]


@pytest.mark.integration
@pytest.mark.parametrize("param, reason", [
    # the share link escapes `*` in a value as %2A
    ("observable_pattern:fqdn:%2Aevil%2A", "has a wildcard at both ends"),
    ("analysis:not-a-module-path", "analysis values must be module paths"),
    ("alert_date:garbage", "invalid date range"),
])
def test_a_share_link_with_a_value_the_filter_refuses_is_refused(web_client, analyst, param, reason):
    """Decoding a link checks its shape, not its values. A value the filter refuses used to reach
    the write of the temporary filter, fail there and answer 500, after the restore point for
    Revert had already been moved."""
    with web_client.session_transaction() as sess:
        _seed_manage_session(sess, analyst)
        filter_uuid = sess["filter_uuid"]

    response = web_client.get(url_for("analysis.manage", f=param))
    assert response.status_code == 302
    assert response.headers["Location"].endswith(url_for("analysis.manage"))

    with web_client.session_transaction() as sess:
        assert sess["filter_uuid"] == filter_uuid
        assert "filter_restore_uuid" not in sess
        messages = [message for _, message in sess.get("_flashes", [])]
    assert len(messages) == 1
    assert messages[0].startswith("That filter link could not be read: ") and reason in messages[0]
    # the reason as the analyst reads it, without pydantic's framing
    assert "pydantic" not in messages[0] and "Value error" not in messages[0]
