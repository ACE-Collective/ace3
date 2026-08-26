"""Tests for the alert management filter routes.

The session carries UUIDs only now -- filter contents live in the saved_filters table -- so
these assert on the resolved filter list and on the state machine keys rather than on a
filter payload in the cookie.
"""

import json

import pytest
from flask import url_for

from saq.gui.filter_url import encode_filter_query


def _effective(web_client):
    """The filter list currently driving the alert list, resolved from the session's uuid."""
    from app.analysis.views.session.filters import get_effective_filters
    return get_effective_filters()


def _apply(web_client, filters):
    return web_client.post(url_for("analysis.set_filters"), data={"filters": json.dumps(filters)})


def _state(web_client):
    with web_client.session_transaction() as sess:
        return dict(sess)


QUEUE = [{"name": "Queue", "inverted": False, "values": ["default"]}]
TAG = [{"name": "Tag", "inverted": False, "values": ["needs_research"]}]


@pytest.mark.integration
def test_set_sort_filter_new_field(web_client):
    """Test setting a new sort filter field."""
    with web_client.session_transaction() as sess:
        sess.clear()
    
    response = web_client.post(url_for("analysis.set_sort_filter"), data={
        "name": "alert_type"
    })
    
    assert response.status_code == 204
    assert response.data == b''
    
    with web_client.session_transaction() as sess:
        assert sess['sort_filter'] == 'alert_type'
        assert sess['sort_filter_desc'] == False
        assert sess['page_offset'] == 0
        assert 'checked' in sess and sess['checked'] == []


@pytest.mark.integration
def test_set_sort_filter_same_field_flips_direction(web_client):
    """Test setting the same sort filter field flips direction."""
    with web_client.session_transaction() as sess:
        sess['sort_filter'] = 'alert_type'
        sess['sort_filter_desc'] = False
    
    response = web_client.post(url_for("analysis.set_sort_filter"), data={
        "name": "alert_type"
    })
    
    assert response.status_code == 204
    
    with web_client.session_transaction() as sess:
        assert sess['sort_filter'] == 'alert_type'
        assert sess['sort_filter_desc'] == True


@pytest.mark.integration
def test_set_sort_filter_get_method(web_client):
    """Test setting sort filter via GET method."""
    response = web_client.get(url_for("analysis.set_sort_filter", name="description"))
    
    assert response.status_code == 204
    
    with web_client.session_transaction() as sess:
        assert sess['sort_filter'] == 'description'
        assert sess['sort_filter_desc'] == False


@pytest.mark.integration
def test_new_filter_option(web_client):
    """Test rendering new filter option template."""
    response = web_client.get(url_for("analysis.new_filter_option"))
    
    assert response.status_code == 200
    assert b'alert_filter_input.html' in response.data or b'Description' in response.data


@pytest.mark.integration
def test_new_filter_option_post(web_client):
    """Test new filter option via POST method."""
    response = web_client.post(url_for("analysis.new_filter_option"))
    
    assert response.status_code == 200


@pytest.mark.integration
def test_set_sort_filter_missing_name_parameter(web_client):
    """Test set_sort_filter with missing name parameter raises BadRequestKeyError."""
    with pytest.raises(Exception):  # Catches BadRequestKeyError or similar
        web_client.post(url_for("analysis.set_sort_filter"))



#
# the session holds identifiers, never filter contents
#

@pytest.mark.integration
def test_session_never_holds_filter_contents(web_client):
    """The whole point of moving filter state into the database: the cookie used to carry a
    multi-KB filter payload, which capped how complex a filter could get and blocked the
    SSE migration (docs/GUI_DATASTAR.md)."""
    _apply(web_client, QUEUE + TAG)

    state = _state(web_client)
    assert "filters" not in state
    for key in ("filter_uuid", "filter_base_uuid", "filter_state", "filter_restore_uuid"):
        value = state.get(key)
        assert value is None or (isinstance(value, str) and len(value) <= 36), key


@pytest.mark.integration
def test_apply_sets_dirty_but_does_not_persist_a_named_filter(web_client):
    """Apply changes what you are looking at. Persisting is always an explicit Save."""
    _apply(web_client, TAG)

    state = _state(web_client)
    assert state["filter_state"] == "dirty"
    assert state["filter_base_uuid"] is None

    from app.analysis.views.session.filters import get_saved_filter_list
    assert get_saved_filter_list() == []


@pytest.mark.integration
def test_apply_rejects_an_unparseable_date(web_client):
    """A bad date must not reach storage. It used to, and then raised on EVERY subsequent
    /manage load -- the analyst's queue stayed broken until someone reset it by hand."""
    response = _apply(web_client, [{"name": "Alert Date", "inverted": False, "values": ["-7dd"]}])
    assert response.status_code == 400


@pytest.mark.integration
def test_apply_rejects_an_unknown_filter_name(web_client):
    response = _apply(web_client, [{"name": "Nonexistent", "inverted": False, "values": ["x"]}])
    assert response.status_code == 400


#
# temporary filters
#

@pytest.mark.integration
def test_pivot_does_not_disturb_the_persistent_selection(web_client):
    """The behaviour this whole feature exists for: clicking an observable from an alert
    used to overwrite the analyst's filter outright."""
    _apply(web_client, QUEUE)
    before = _state(web_client)

    response = web_client.post(url_for("analysis.apply_temp_filter"),
                               data={"filters": json.dumps(TAG), "label": "Tag: needs_research"})
    assert response.status_code == 204

    after = _state(web_client)
    assert after["filter_state"] == "temp"
    assert after["filter_base_uuid"] == before["filter_base_uuid"]
    assert after["filter_restore_uuid"] == before["filter_uuid"]
    assert [f["name"] for f in _effective(web_client)] == ["Tag"]


@pytest.mark.integration
def test_revert_restores_the_previous_filter_exactly(web_client):
    _apply(web_client, QUEUE)
    before_uuid = _state(web_client)["filter_uuid"]

    web_client.post(url_for("analysis.apply_temp_filter"),
                    data={"filters": json.dumps(TAG), "label": "Tag"})
    assert web_client.get(url_for("analysis.revert_temp_filter")).status_code == 204

    after = _state(web_client)
    assert after["filter_uuid"] == before_uuid
    assert after["filter_state"] != "temp"
    assert [f["name"] for f in _effective(web_client)] == ["Queue"]


@pytest.mark.integration
def test_a_second_pivot_does_not_overwrite_the_restore_point(web_client):
    """Two pivots deep, Revert must still land on the analyst's real filter rather than on
    the first pivot."""
    _apply(web_client, QUEUE)
    original_uuid = _state(web_client)["filter_uuid"]

    for label in ("first", "second"):
        web_client.post(url_for("analysis.apply_temp_filter"),
                        data={"filters": json.dumps(TAG), "label": label})

    assert _state(web_client)["filter_restore_uuid"] == original_uuid

    web_client.get(url_for("analysis.revert_temp_filter"))
    assert [f["name"] for f in _effective(web_client)] == ["Queue"]


@pytest.mark.integration
def test_revert_without_a_temp_is_a_404(web_client):
    _apply(web_client, QUEUE)
    assert web_client.get(url_for("analysis.revert_temp_filter")).status_code == 404


@pytest.mark.integration
def test_editing_while_temp_is_active_refines_the_temp(web_client):
    """An edit on top of a pivot must not quietly become an edit of the real filter."""
    _apply(web_client, QUEUE)
    base_before = _state(web_client)["filter_base_uuid"]

    web_client.post(url_for("analysis.apply_temp_filter"),
                    data={"filters": json.dumps(TAG), "label": "Tag"})
    _apply(web_client, TAG + QUEUE)

    after = _state(web_client)
    assert after["filter_state"] == "temp"
    assert after["filter_base_uuid"] == base_before


#
# saved filters
#

@pytest.mark.integration
def test_save_as_then_select(web_client):
    _apply(web_client, TAG)
    response = web_client.post(url_for("analysis.create_saved_filter"), data={"name": "Research"})
    assert response.status_code == 200

    filter_uuid = response.get_json()["uuid"]
    state = _state(web_client)
    assert state["filter_base_uuid"] == filter_uuid
    assert state["filter_state"] == "clean"

    _apply(web_client, QUEUE)
    assert web_client.get(url_for("analysis.select_filter", filter_uuid=filter_uuid)).status_code == 204
    assert [f["name"] for f in _effective(web_client)] == ["Tag"]


@pytest.mark.integration
def test_duplicate_name_is_a_conflict(web_client):
    _apply(web_client, TAG)
    web_client.post(url_for("analysis.create_saved_filter"), data={"name": "Dupe"})
    response = web_client.post(url_for("analysis.create_saved_filter"), data={"name": "Dupe"})
    assert response.status_code == 409


@pytest.mark.integration
def test_deleting_the_selected_filter_leaves_a_usable_page(web_client):
    """A dangling uuid must degrade to the default set rather than 500 on a page the analyst
    cannot escape without clearing cookies."""
    _apply(web_client, TAG)
    filter_uuid = web_client.post(
        url_for("analysis.create_saved_filter"), data={"name": "Doomed"}).get_json()["uuid"]

    assert web_client.post(
        url_for("analysis.delete_saved_filter", filter_uuid=filter_uuid)).status_code == 204
    assert _state(web_client)["filter_base_uuid"] is None
    assert web_client.get(url_for("analysis.manage")).status_code == 200


@pytest.mark.integration
def test_select_unknown_filter_is_a_404(web_client):
    assert web_client.get(url_for("analysis.select_filter", filter_uuid="nope")).status_code == 404


#
# durable share links
#

@pytest.mark.integration
def test_share_link_applies_as_a_temporary_filter(web_client):
    """Opening someone's link must not clobber the filter you were already using."""
    _apply(web_client, QUEUE)
    before = _state(web_client)

    response = web_client.get(url_for("analysis.manage"), query_string={"f": ["tag:needs_research"]})
    assert response.status_code == 200

    after = _state(web_client)
    assert after["filter_state"] == "temp"
    assert after["filter_base_uuid"] == before["filter_base_uuid"]


@pytest.mark.integration
def test_share_link_keeps_its_params_in_the_url(web_client):
    """A durable link has to stay visible to be copied, bookmarked, and reachable with the
    back button -- so this deliberately does NOT redirect to a bare /manage."""
    response = web_client.get(url_for("analysis.manage"), query_string={"f": ["tag:x"]})
    assert response.status_code == 200, "a redirect here would strip the canonical URL"


@pytest.mark.integration
def test_share_link_survives_the_author_deleting_every_saved_filter(web_client):
    """The reason links are self-describing rather than a row id."""
    params = encode_filter_query(TAG)
    _apply(web_client, TAG)
    filter_uuid = web_client.post(
        url_for("analysis.create_saved_filter"), data={"name": "Shared"}).get_json()["uuid"]
    web_client.post(url_for("analysis.delete_saved_filter", filter_uuid=filter_uuid))

    assert web_client.get(url_for("analysis.manage"), query_string={"f": params}).status_code == 200
    assert [f["name"] for f in _effective(web_client)] == ["Tag"]


@pytest.mark.integration
def test_unknown_slug_is_skipped_and_the_rest_applied(web_client):
    response = web_client.get(url_for("analysis.manage"),
                              query_string={"f": ["queue:default", "obsolete:x"]})

    assert response.status_code == 200
    assert [f["name"] for f in _effective(web_client)] == ["Queue"]


@pytest.mark.integration
def test_malformed_share_link_does_not_500(web_client):
    response = web_client.get(url_for("analysis.manage"), query_string={"f": ["noseparator"]},
                              follow_redirects=True)
    assert response.status_code == 200


#
# legacy links -- permanently supported
#

@pytest.mark.integration
def test_legacy_link_redirects_to_the_canonical_format(web_client):
    """Old links are already pasted in wikis and tickets. Following one lands the analyst on
    a new-format URL, so what they copy onward stops propagating the old shape."""
    legacy = json.dumps(TAG)
    response = web_client.get(url_for("analysis.set_filters"),
                              query_string={"redirect": "1", "filters": legacy})

    assert response.status_code == 302
    assert "/manage?" in response.headers["Location"]
    assert "f=tag" in response.headers["Location"]


@pytest.mark.integration
def test_legacy_link_yields_the_same_filters_as_the_modern_one(web_client):
    """The property that makes the redirect lossless."""
    legacy = json.dumps([{"name": "Observable", "inverted": False,
                          "values": [["url", "https://evil.com/a,b:c"]]}])
    response = web_client.get(url_for("analysis.set_filters"),
                              query_string={"redirect": "1", "filters": legacy})
    web_client.get(response.headers["Location"])
    via_legacy = _effective(web_client)

    web_client.get(url_for("analysis.manage"), query_string={"f": encode_filter_query([
        {"name": "Observable", "inverted": False, "values": [["url", "https://evil.com/a,b:c"]]}])})

    assert via_legacy == _effective(web_client)


@pytest.mark.integration
def test_legacy_get_no_longer_mutates_state(web_client):
    """It used to be a mutating GET, so any prefetch or link scanner could rewrite an
    analyst's filters. It is a pure translation now."""
    _apply(web_client, QUEUE)
    before = _state(web_client)

    web_client.get(url_for("analysis.set_filters"),
                   query_string={"redirect": "1", "filters": json.dumps(TAG)})

    assert _state(web_client) == before


@pytest.mark.integration
def test_manage_also_accepts_the_legacy_param(web_client):
    response = web_client.get(url_for("analysis.manage"), query_string={"filters": json.dumps(TAG)})
    assert response.status_code == 302
    assert "f=tag" in response.headers["Location"]


#
# reset
#

@pytest.mark.integration
def test_reset_clears_all_filter_state(web_client, analyst):
    _apply(web_client, TAG)
    web_client.post(url_for("analysis.apply_temp_filter"),
                    data={"filters": json.dumps(QUEUE), "label": "x"})

    assert web_client.get(url_for("analysis.reset_filters")).status_code == 204

    state = _state(web_client)
    assert state["filter_state"] == "clean"
    assert state["filter_base_uuid"] is None
    assert state.get("filter_restore_uuid") is None
    assert {f["name"] for f in _effective(web_client)} == {"Disposition", "Owner", "Queue"}


@pytest.mark.integration
def test_removing_a_filter_category(web_client):
    _apply(web_client, QUEUE + TAG)
    web_client.get(url_for("analysis.remove_filter_category", name="Tag"))

    assert [f["name"] for f in _effective(web_client)] == ["Queue"]


@pytest.mark.integration
def test_removing_a_single_value_drops_the_empty_filter(web_client):
    _apply(web_client, TAG)
    web_client.get(url_for("analysis.remove_filter", name="Tag", index=0))

    assert _effective(web_client) == []
