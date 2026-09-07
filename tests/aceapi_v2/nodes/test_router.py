"""Tests for aceapi_v2 nodes router."""

from datetime import datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from saq.constants import (
    NODE_EXPECTED_STATE_OFFLINE,
    NODE_EXPECTED_STATE_ONLINE,
    NODE_STATUS_DRAINED,
    NODE_STATUS_DRAINING,
    NODE_STATUS_DRAINING_COLLECTORS,
    NODE_STATUS_RUNNING,
    NODE_STATUS_STOPPED,
)
from saq.database.model import CollectorStatus, Company, DelayedAnalysis, Nodes, Workload

pytestmark = pytest.mark.integration


async def create_node(
        session: AsyncSession,
        name: str = "test_api_node",
        status: str = NODE_STATUS_RUNNING,
        expected_state: str = NODE_EXPECTED_STATE_ONLINE) -> Nodes:
    company = (await session.execute(select(Company))).scalars().first()
    node = Nodes(
        name=name,
        location=f"{name}:443",
        company_id=company.id,
        last_update=datetime.now(),
        status=status,
        expected_state=expected_state,
    )
    session.add(node)
    await session.commit()
    return node


class TestNodesRouter:

    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.get("/nodes/")
        assert response.status_code == 401

        response = await unauth_client.post("/nodes/1/drain")
        assert response.status_code == 401

        response = await unauth_client.post("/nodes/1/resume")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_list_nodes(self, session: AsyncSession, client: AsyncClient):
        node = await create_node(session)

        response = await client.get("/nodes/")
        assert response.status_code == 200
        data = response.json()["data"]
        entry = next(_ for _ in data if _["id"] == node.id)
        assert entry["name"] == "test_api_node"
        assert entry["status"] == NODE_STATUS_RUNNING
        assert entry["workload_count"] == 0
        assert entry["delayed_analysis_count"] == 0
        assert entry["collectors"] == []

    @pytest.mark.asyncio
    async def test_get_node_with_counts(self, session: AsyncSession, client: AsyncClient):
        node = await create_node(session)

        session.add(Workload(
            uuid="b18e1039-cbe9-49f1-b507-d4429e9d0b3c",
            node_id=node.id,
            analysis_mode="analysis",
            company_id=node.company_id,
            storage_dir="data/test/x",
            insert_date=datetime.now()))
        session.add(DelayedAnalysis(
            uuid="c28e1039-cbe9-49f1-b507-d4429e9d0b3c",
            observable_uuid="d38e1039-cbe9-49f1-b507-d4429e9d0b3c",
            analysis_module="test_module",
            insert_date=datetime.now(),
            delayed_until=datetime.now(),
            node_id=node.id,
            storage_dir="data/test/y"))
        session.add(CollectorStatus(
            node_id=node.id,
            name="email",
            status=NODE_STATUS_RUNNING,
            backlog_count=2,
            last_update=datetime.now()))
        await session.commit()

        response = await client.get(f"/nodes/{node.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["workload_count"] == 1
        assert data["delayed_analysis_count"] == 1
        assert len(data["collectors"]) == 1
        assert data["collectors"][0]["name"] == "email"
        assert data["collectors"][0]["status"] == NODE_STATUS_RUNNING
        assert data["collectors"][0]["backlog_count"] == 2

    @pytest.mark.asyncio
    async def test_get_node_not_found(self, client: AsyncClient):
        response = await client.get("/nodes/999999999")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_drain_running_node(self, session: AsyncSession, client: AsyncClient):
        node = await create_node(session, status=NODE_STATUS_RUNNING)

        response = await client.post(f"/nodes/{node.id}/drain")
        assert response.status_code == 200
        assert response.json()["status"] == NODE_STATUS_DRAINING_COLLECTORS
        # the drain is the only signal that a shutdown is planned, and it has to outlive
        # the status: the node reaches stopped either way, drained first or crashed
        assert response.json()["expected_state"] == NODE_EXPECTED_STATE_OFFLINE

    @pytest.mark.asyncio
    async def test_drain_invalid_status(self, session: AsyncSession, client: AsyncClient):
        for status in [NODE_STATUS_STOPPED, NODE_STATUS_DRAINING_COLLECTORS, NODE_STATUS_DRAINING, NODE_STATUS_DRAINED]:
            node = await create_node(session, name=f"test_api_node_{status}", status=status)

            response = await client.post(f"/nodes/{node.id}/drain")
            assert response.status_code == 409
            assert status in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_drain_unknown_node(self, client: AsyncClient):
        response = await client.post("/nodes/999999999/drain")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_resume_draining_collectors_node(self, session: AsyncSession, client: AsyncClient):
        node = await create_node(session, status=NODE_STATUS_DRAINING_COLLECTORS)

        response = await client.post(f"/nodes/{node.id}/resume")
        assert response.status_code == 200
        assert response.json()["status"] == NODE_STATUS_RUNNING

    @pytest.mark.asyncio
    async def test_resume_draining_node(self, session: AsyncSession, client: AsyncClient):
        node = await create_node(session, status=NODE_STATUS_DRAINING)

        response = await client.post(f"/nodes/{node.id}/resume")
        assert response.status_code == 200
        assert response.json()["status"] == NODE_STATUS_RUNNING

    @pytest.mark.asyncio
    async def test_resume_drained_node(self, session: AsyncSession, client: AsyncClient):
        node = await create_node(session, status=NODE_STATUS_DRAINED)

        response = await client.post(f"/nodes/{node.id}/resume")
        assert response.status_code == 200
        assert response.json()["status"] == NODE_STATUS_RUNNING

    @pytest.mark.asyncio
    async def test_resume_invalid_status(self, session: AsyncSession, client: AsyncClient):
        for status in [NODE_STATUS_RUNNING, NODE_STATUS_STOPPED]:
            node = await create_node(session, name=f"test_api_node_{status}", status=status)

            response = await client.post(f"/nodes/{node.id}/resume")
            assert response.status_code == 409
            assert status in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_resume_unknown_node(self, client: AsyncClient):
        response = await client.post("/nodes/999999999/resume")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_drain_then_resume_round_trip(self, session: AsyncSession, client: AsyncClient):
        node = await create_node(session, status=NODE_STATUS_RUNNING)

        response = await client.post(f"/nodes/{node.id}/drain")
        assert response.status_code == 200
        assert response.json()["status"] == NODE_STATUS_DRAINING_COLLECTORS

        # draining a draining node fails
        response = await client.post(f"/nodes/{node.id}/drain")
        assert response.status_code == 409

        response = await client.post(f"/nodes/{node.id}/resume")
        assert response.status_code == 200
        assert response.json()["status"] == NODE_STATUS_RUNNING

    @pytest.mark.asyncio
    async def test_resume_marks_the_node_expected_online(self, session: AsyncSession, client: AsyncClient):
        node = await create_node(session, status=NODE_STATUS_DRAINED,
                                 expected_state=NODE_EXPECTED_STATE_OFFLINE)

        response = await client.post(f"/nodes/{node.id}/resume")
        assert response.status_code == 200
        assert response.json()["status"] == NODE_STATUS_RUNNING
        assert response.json()["expected_state"] == NODE_EXPECTED_STATE_ONLINE

    @pytest.mark.asyncio
    async def test_intent_is_not_written_when_the_transition_is_rejected(
            self, session: AsyncSession, client: AsyncClient):
        """A drain that loses the race must not leave the node marked offline -- that would
        silence monitoring for a node nobody actually drained."""
        node = await create_node(session, name="test_api_node_rejected_drain",
                                 status=NODE_STATUS_STOPPED)

        response = await client.post(f"/nodes/{node.id}/drain")
        assert response.status_code == 409

        await session.refresh(node)
        assert node.expected_state == NODE_EXPECTED_STATE_ONLINE
