"""The AI app's search routes: ai:search gating over the shared v2 search service, audit lines,
and the rate limiter."""

import json
import uuid
from unittest.mock import Mock

import pytest
import pytest_asyncio

from aceapi_ai.ratelimit import RateLimitExceeded, RateLimitUnavailable
from aceapi_v2.search import service as v2_service
from saq.search.types import AlertSearchResult, SearchResponse

pytestmark = pytest.mark.integration


def _stub(monkeypatch, alert_uuids):
    results = [AlertSearchResult(alert_uuid=u, rank=i + 1, fused_score=0.5, tier="good", lanes=frozenset({"semantic"})) for i, u in enumerate(alert_uuids)]
    response = SearchResponse(query="q", total=len(results), offset=0, limit=20, results=results, lanes_used=frozenset({"semantic"}))
    monkeypatch.setattr(v2_service, "search_alerts", Mock(return_value=response))
    monkeypatch.setattr(v2_service, "similar_alerts", Mock(return_value=response))


@pytest_asyncio.fixture
async def search_client(_override_db_session, session, test_user):
    from tests.aceapi_ai.conftest import api_key_client
    from tests.aceapi_v2.conftest import make_api_key

    key = await make_api_key(session, test_user.id, inherit=False, scope=[("ai", "search")])
    async with api_key_client(key) as client:
        yield client


@pytest.mark.asyncio
async def test_search_requires_auth(unauth_client):
    assert (await unauth_client.post("/search/alerts", json={"query": "x"})).status_code == 401


@pytest.mark.asyncio
async def test_search_requires_ai_search_scope(ai_scoped_client):
    """A key with ai:alert + ai:event (the pre-existing AI scope) does not reach search."""
    assert (await ai_scoped_client.post("/search/alerts", json={"query": "x"})).status_code == 403
    assert (await ai_scoped_client.post("/search/similar", json={"alert_uuid": str(uuid.uuid4())})).status_code == 403


@pytest.mark.asyncio
async def test_search_returns_results_and_audits(search_client, monkeypatch, caplog):
    from tests.saq.helpers import insert_alert

    alert = insert_alert()
    _stub(monkeypatch, [alert.uuid])

    with caplog.at_level("INFO", logger="ace.ai_audit"):
        response = await search_client.post("/search/alerts", json={"query": "docusign invoice", "filters": {"dispositions": ["DELIVERY"]}})

    assert response.status_code == 200, response.text
    data = response.json()
    assert [r["alert"]["uuid"] for r in data["results"]] == [alert.uuid]
    assert data["results"][0]["alert"]["disposition"] == alert.disposition

    lines = [r.message for r in caplog.records if r.name == "ace.ai_audit"]
    assert len(lines) == 1
    event = json.loads(lines[0].removeprefix("AI_AUDIT "))
    assert event["event"] == "search"
    assert event["query"] == "docusign invoice"
    assert event["filters"]["dispositions"] == ["DELIVERY"]
    assert event["result_uuids"] == [alert.uuid]
    assert event["status"] == 200


@pytest.mark.asyncio
async def test_similar_audits_alert_uuid(search_client, monkeypatch, caplog):
    from tests.saq.helpers import insert_alert

    source = insert_alert()
    neighbour = insert_alert()
    _stub(monkeypatch, [neighbour.uuid])

    with caplog.at_level("INFO", logger="ace.ai_audit"):
        response = await search_client.post("/search/similar", json={"alert_uuid": source.uuid})

    assert response.status_code == 200, response.text
    event = json.loads([r.message for r in caplog.records if r.name == "ace.ai_audit"][0].removeprefix("AI_AUDIT "))
    assert event["event"] == "similar" and event["alert_uuid"] == source.uuid


@pytest.mark.asyncio
async def test_rate_limited_search_is_429_with_retry_after(search_client, monkeypatch, caplog):
    import aceapi_ai.search.service as service_module

    def refuse(backend_name, limits):
        assert backend_name == service_module.SEARCH_LIMIT_NAME
        raise RateLimitExceeded("rate", "simulated exhaustion", retry_after_seconds=17)

    monkeypatch.setattr(service_module.rate_limiter, "check_request", refuse)
    with caplog.at_level("INFO", logger="ace.ai_audit"):
        response = await search_client.post("/search/alerts", json={"query": "x"})

    assert response.status_code == 429
    assert response.headers["retry-after"] == "17"
    event = json.loads([r.message for r in caplog.records if r.name == "ace.ai_audit"][0].removeprefix("AI_AUDIT "))
    assert event["event"] == "rate_limited"


@pytest.mark.asyncio
async def test_unavailable_limiter_is_503(search_client, monkeypatch):
    import aceapi_ai.search.service as service_module

    def unavailable(backend_name, limits):
        raise RateLimitUnavailable("redis down")

    monkeypatch.setattr(service_module.rate_limiter, "check_request", unavailable)
    assert (await search_client.post("/search/alerts", json={"query": "x"})).status_code == 503
