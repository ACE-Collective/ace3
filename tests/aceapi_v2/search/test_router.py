"""Tests for the aceapi_v2 search routes: auth/permission gating, request validation, and the
response shape. The search itself is exercised in tests/saq/search; here it is stubbed."""

from datetime import datetime, timezone
from unittest.mock import Mock

import pytest
from httpx import AsyncClient

from aceapi_v2.search import service
from saq.search.types import LANE_LEXICAL, LANE_SEMANTIC, AlertSearchResult, SearchHit, SearchResponse
from tests.saq.helpers import insert_alert

pytestmark = pytest.mark.integration

SIGNATURE_UUID = "6f3a1b2c-1111-2222-3333-444455556666"


def _stub_response(monkeypatch, alert_uuids, query="q"):
    results = [
        AlertSearchResult(alert_uuid=u, rank=i + 1, fused_score=1.0 / (i + 1), tier="exact" if i == 0 else "good",
                          hits=[SearchHit(lane=LANE_LEXICAL if i == 0 else LANE_SEMANTIC, kind="observable" if i == 0 else "comment", key="k", title="t", text="hit text", score=1.0)],
                          lanes=frozenset({LANE_LEXICAL if i == 0 else LANE_SEMANTIC}))
        for i, u in enumerate(alert_uuids)
    ]
    response = SearchResponse(query=query, total=len(results), offset=0, limit=20, results=results, lanes_used=frozenset({LANE_LEXICAL, LANE_SEMANTIC}), timings_ms={"lexical": 1})
    search = Mock(return_value=response)
    similar = Mock(return_value=response)
    monkeypatch.setattr(service, "search_alerts", search)
    monkeypatch.setattr(service, "similar_alerts", similar)
    return search, similar


class TestSearchAlerts:
    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        assert (await unauth_client.post("/search/alerts", json={"query": "x"})).status_code == 401

    @pytest.mark.asyncio
    async def test_requires_alert_read(self, noperm_client: AsyncClient):
        assert (await noperm_client.post("/search/alerts", json={"query": "x"})).status_code == 403
        assert (await noperm_client.post("/search/similar", json={"alert_uuid": "x"})).status_code == 403

    @pytest.mark.asyncio
    async def test_validation(self, client: AsyncClient):
        assert (await client.post("/search/alerts", json={"query": ""})).status_code == 422
        assert (await client.post("/search/alerts", json={})).status_code == 422
        assert (await client.post("/search/alerts", json={"query": "x", "limit": 1000})).status_code == 422
        assert (await client.post("/search/alerts", json={"query": "x", "lanes": ["bogus"]})).status_code == 422
        naive = {"query": "x", "filters": {"insert_date_start": "2026-01-01T00:00:00"}}
        assert (await client.post("/search/alerts", json=naive)).status_code == 422
        bad_filter = {"query": "x", "filters": {"filters": [{"name": "No Such Filter", "values": ["x"]}]}}
        assert (await client.post("/search/alerts", json=bad_filter)).status_code == 422

    @pytest.mark.asyncio
    async def test_filters_alone_are_enough(self, client: AsyncClient, monkeypatch):
        """No query at all is a valid request: it is a listing, not a search."""
        alert = insert_alert()
        search, _ = _stub_response(monkeypatch, [alert.uuid])
        response = await client.post("/search/alerts", json={
            "filters": {"observables": [{"type": "signature_id", "value": SIGNATURE_UUID}]}})
        assert response.status_code == 200, response.text
        request = search.call_args[0][0]
        assert request.query == ""
        assert request.filters.filter_list == (
            {"name": "Observable", "inverted": False, "values": [["signature_id", SIGNATURE_UUID]]},)

    @pytest.mark.asyncio
    async def test_detection_points_filter(self, client: AsyncClient, monkeypatch):
        """`detection_points` is sugar for ONE Detection Point entry (its values are ORed),
        with the signature uuid normalized on the way in."""
        alert = insert_alert()
        search, _ = _stub_response(monkeypatch, [alert.uuid])
        response = await client.post("/search/alerts", json={
            "filters": {"detection_points": [SIGNATURE_UUID.upper(), f"{SIGNATURE_UUID}:abc:123"]}})
        assert response.status_code == 200, response.text
        request = search.call_args[0][0]
        assert request.filters.filter_list == (
            {"name": "Detection Point", "inverted": False, "values": [SIGNATURE_UUID, f"{SIGNATURE_UUID}:abc:123"]},)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("value", ["not-a-uuid", f"{SIGNATURE_UUID}:"])
    async def test_detection_points_filter_rejects_a_bad_value(self, client: AsyncClient, value):
        response = await client.post("/search/alerts", json={"filters": {"detection_points": [value]}})
        assert response.status_code == 422
        bad_entry = {"filters": {"filters": [{"name": "Detection Point", "values": [value]}]}}
        assert (await client.post("/search/alerts", json=bad_entry)).status_code == 422

    @pytest.mark.asyncio
    async def test_observable_filter_rejects_an_impossible_value(self, client: AsyncClient):
        response = await client.post("/search/alerts", json={
            "filters": {"observables": [{"type": "ipv4", "value": "not-an-ip"}]}})
        assert response.status_code == 400
        assert "ipv4" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_query_language_errors_are_returned(self, client: AsyncClient):
        """A term the parser cannot honor is reported. Nothing is searched: silently dropping
        it would answer a wider question than the one that was asked."""
        response = await client.post("/search/alerts", json={"query": "alert_date:-7dd"})
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["total"] == 0 and data["results"] == []
        assert data["errors"] and "time window" in data["errors"][0]

    @pytest.mark.asyncio
    async def test_response_shape_and_filter_translation(self, client: AsyncClient, monkeypatch):
        first = insert_alert()
        second = insert_alert()
        search, _ = _stub_response(monkeypatch, [first.uuid, second.uuid, "00000000-0000-0000-0000-000000000000"])

        response = await client.post("/search/alerts", json={
            "query": "ipv4:10.20.30.40",
            "filters": {
                "dispositions": ["OPEN"],
                "tags": ["Credential-Harvest"],
                "insert_date_start": "2026-01-01T00:00:00Z",
                "observables": [{"type": "signature_id", "value": SIGNATURE_UUID}],
                "filters": [{"name": "Owner", "inverted": True, "values": ["None"]}],
            },
            "limit": 5,
        })
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["total"] == 3
        assert data["lanes_used"] == ["lexical", "semantic"]
        # an alert the database does not know is dropped from the page rather than 500ing
        assert [r["alert"]["uuid"] for r in data["results"]] == [first.uuid, second.uuid]
        top = data["results"][0]
        assert top["tier"] == "exact" and top["rank"] == 1 and top["lanes"] == ["lexical"]
        assert top["hits"][0] == {"lane": "lexical", "kind": "observable", "title": "t", "text": "hit text", "score": 1.0}
        assert top["alert"]["disposition"] == "OPEN"
        assert top["alert"]["description"] == first.description
        assert "insert_date" in top["alert"] and "tags" in top["alert"]

        request = search.call_args[0][0]
        assert request.query == "ipv4:10.20.30.40" and request.limit == 5
        assert request.filters.dispositions == ("OPEN",)
        assert request.filters.tags == ("credential-harvest",)
        # the GUI filter vocabulary comes through verbatim; `observables` is sugar for an
        # Observable entry, with its value normalized on the way in
        assert request.filters.filter_list == (
            {"name": "Owner", "inverted": True, "values": ["None"]},
            {"name": "Observable", "inverted": False, "values": [["signature_id", SIGNATURE_UUID]]},
        )
        assert request.filters.insert_date_ranges[0][0] == datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert request.filters.locations is not None  # node scoping is always applied
        assert search.call_args.kwargs["post_filter"] is service.node_scope_post_filter


class TestSimilarAlerts:
    @pytest.mark.asyncio
    async def test_invalid_and_missing_alert(self, client: AsyncClient):
        assert (await client.post("/search/similar", json={"alert_uuid": "nope"})).status_code == 400
        assert (await client.post("/search/similar", json={"alert_uuid": "00000000-0000-0000-0000-000000000000"})).status_code == 404

    @pytest.mark.asyncio
    async def test_similar(self, client: AsyncClient, monkeypatch):
        source = insert_alert()
        neighbour = insert_alert()
        _, similar = _stub_response(monkeypatch, [neighbour.uuid], query=f"similar:{source.uuid}")

        response = await client.post("/search/similar", json={"alert_uuid": source.uuid, "limit": 3})
        assert response.status_code == 200, response.text
        assert [r["alert"]["uuid"] for r in response.json()["results"]] == [neighbour.uuid]
        assert similar.call_args[0][0] == source.uuid
        assert similar.call_args.kwargs["limit"] == 3


class TestNodeScoping:
    @pytest.mark.integration
    def test_post_filter_preserves_order_and_drops_unknown(self):
        first = insert_alert()
        second = insert_alert()
        assert service.node_scope_post_filter([second.uuid, "missing", first.uuid]) == [second.uuid, first.uuid]
        assert service.node_scope_post_filter([]) == []
