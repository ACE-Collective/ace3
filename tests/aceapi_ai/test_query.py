"""Endpoint contract tests for the AI query routes, driven by the fake backend."""

import json
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.integration


def query_body(**kwargs) -> dict:
    end = datetime.now(timezone.utc)
    body = {
        "query": "search something",
        "start_time": (end - timedelta(hours=1)).isoformat(),
        "end_time": end.isoformat(),
    }
    body.update(kwargs)
    return body


class TestAuthentication:
    @pytest.mark.asyncio
    async def test_query_requires_auth(self, unauth_client):
        response = await unauth_client.post("/query/fake", json=query_body())
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_query_rejects_unknown_key(self, unauth_client):
        response = await unauth_client.post(
            "/query/fake", json=query_body(),
            headers={"x-ace-auth": "00000000-0000-0000-0000-000000000000"})
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_scoped_key_denied_on_unscoped_backend(self, ai_scoped_client):
        # the key carries ai:fake + ai:alert; the splunk backend route requires ai:splunk
        response = await ai_scoped_client.post("/query/splunk", json=query_body())
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_scoped_key_allowed_on_scoped_backend(self, ai_scoped_client):
        response = await ai_scoped_client.post("/query/fake", json=query_body())
        assert response.status_code == 200


class TestQueryContract:
    @pytest.mark.asyncio
    async def test_successful_query_shape(self, client):
        response = await client.post("/query/fake", json=query_body())
        assert response.status_code == 200
        data = response.json()
        assert data["backend"] == "fake"
        assert data["row_count"] == len(data["rows"]) == 2
        assert data["truncated"] is False
        assert data["truncation_reason"] is None
        assert data["meta"] == {"fake": True}
        # the window actually covered is echoed back
        assert data["window_start"] is not None and data["window_end"] is not None

    @pytest.mark.asyncio
    async def test_truncation_is_loud(self, client):
        response = await client.post("/query/fake", json=query_body(extras={"simulate": "truncated"}))
        assert response.status_code == 200
        data = response.json()
        assert data["truncated"] is True
        assert data["truncation_reason"] == "backend_cap"

    @pytest.mark.asyncio
    async def test_backend_rejection_is_400(self, client):
        response = await client.post("/query/fake", json=query_body(extras={"simulate": "rejected"}))
        assert response.status_code == 400
        assert "simulated rejection" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_invalid_extras_is_400(self, client):
        response = await client.post("/query/fake", json=query_body(extras={"sleep_seconds": "not-a-number"}))
        assert response.status_code == 400
        assert "invalid extras" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_backend_error_maps_status(self, client):
        response = await client.post(
            "/query/fake",
            json=query_body(extras={"simulate": "backend_error", "error_status_code": 504}))
        assert response.status_code == 504

        response = await client.post(
            "/query/fake",
            json=query_body(extras={"simulate": "backend_error", "error_status_code": 502}))
        assert response.status_code == 502

    @pytest.mark.asyncio
    async def test_naive_datetime_is_422(self, client):
        response = await client.post(
            "/query/fake", json=query_body(start_time="2026-01-01T00:00:00"))
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_timeout_over_max_is_400(self, client):
        response = await client.post("/query/fake", json=query_body(timeout_seconds=999999))
        assert response.status_code == 400
        assert "timeout_seconds" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_unknown_backend_is_404(self, client):
        response = await client.post("/query/nonexistent", json=query_body())
        assert response.status_code == 404


class TestAudit:
    @pytest.mark.asyncio
    async def test_query_emits_audit_line(self, client, caplog):
        with caplog.at_level("INFO", logger="ace.ai_audit"):
            response = await client.post("/query/fake", json=query_body(query="search audit-me"))
        assert response.status_code == 200

        audit_lines = [r.message for r in caplog.records if r.name == "ace.ai_audit"]
        assert len(audit_lines) == 1
        event = json.loads(audit_lines[0].removeprefix("AI_AUDIT "))
        assert event["event"] == "query"
        assert event["backend"] == "fake"
        assert event["query"] == "search audit-me"
        assert event["user"] == "unittest"
        assert event["key_name"] == "test"
        assert event["key_id"] is not None
        assert event["row_count"] == 2
        assert event["truncated"] is False

    @pytest.mark.asyncio
    async def test_rejection_emits_audit_line(self, client, caplog):
        with caplog.at_level("INFO", logger="ace.ai_audit"):
            response = await client.post("/query/fake", json=query_body(extras={"simulate": "rejected"}))
        assert response.status_code == 400

        audit_lines = [r.message for r in caplog.records if r.name == "ace.ai_audit"]
        assert len(audit_lines) == 1
        event = json.loads(audit_lines[0].removeprefix("AI_AUDIT "))
        assert event["event"] == "query_rejected"


class TestBackendDiscovery:
    @pytest.mark.asyncio
    async def test_backends_requires_auth(self, unauth_client):
        response = await unauth_client.get("/backends")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_backends_reports_authorization(self, ai_scoped_client):
        response = await ai_scoped_client.get("/backends")
        assert response.status_code == 200
        by_name = {b["name"]: b for b in response.json()}
        assert by_name["fake"]["authorized"] is True
        assert by_name["splunk"]["authorized"] is False
        assert by_name["fake"]["describe"]["query_language"] == "fake"
        assert "extras_schema" in by_name["fake"]["describe"]

    @pytest.mark.asyncio
    async def test_backends_inherit_key_authorized_everywhere(self, client):
        response = await client.get("/backends")
        assert response.status_code == 200
        assert all(b["authorized"] for b in response.json())
