"""Node service for ACE API v2."""

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.nodes.schemas import CollectorStatusRead, NodeRead
from saq.constants import (
    NODE_EXPECTED_STATE_OFFLINE,
    NODE_EXPECTED_STATE_ONLINE,
    NODE_STATUS_DRAINED,
    NODE_STATUS_DRAINING,
    NODE_STATUS_DRAINING_COLLECTORS,
    NODE_STATUS_RUNNING,
)
from saq.database.model import CollectorStatus, DelayedAnalysis, Nodes, Workload


async def _build_node_read(session: AsyncSession, node: Nodes) -> NodeRead:
    workload_count = (await session.execute(
        select(func.count()).select_from(Workload).where(Workload.node_id == node.id))).scalar_one()

    delayed_analysis_count = (await session.execute(
        select(func.count()).select_from(DelayedAnalysis).where(DelayedAnalysis.node_id == node.id))).scalar_one()

    collectors = (await session.execute(
        select(CollectorStatus).where(CollectorStatus.node_id == node.id).order_by(CollectorStatus.name))).scalars().all()

    return NodeRead(
        id=node.id,
        name=node.name,
        location=node.location,
        company_id=node.company_id,
        status=node.status,
        expected_state=node.expected_state,
        last_update=node.last_update,
        is_primary=node.is_primary,
        any_mode=node.any_mode,
        workload_count=workload_count,
        delayed_analysis_count=delayed_analysis_count,
        collectors=[
            CollectorStatusRead(
                name=c.name,
                status=c.status,
                backlog_count=c.backlog_count,
                last_update=c.last_update,
            )
            for c in collectors
        ],
    )


async def get_nodes(session: AsyncSession) -> list[NodeRead]:
    result = await session.execute(select(Nodes).order_by(Nodes.name))
    return [await _build_node_read(session, node) for node in result.scalars().all()]


async def get_node(session: AsyncSession, node_id: int) -> NodeRead | None:
    result = await session.execute(select(Nodes).where(Nodes.id == node_id))
    node = result.scalar_one_or_none()
    if node is None:
        return None

    return await _build_node_read(session, node)


async def get_node_status(session: AsyncSession, node_id: int) -> str | None:
    result = await session.execute(select(Nodes.status).where(Nodes.id == node_id))
    return result.scalar_one_or_none()


async def transition_node_status(
        session: AsyncSession,
        node_id: int,
        to_status: str,
        from_statuses: list[str],
        expected_state: str | None = None) -> bool:
    """Atomically transitions the node status. Returns True if the transition occurred.

    When expected_state is given it is written in the same statement, so operator
    intent can never disagree with the status transition that carried it."""
    values = {"status": to_status}
    if expected_state is not None:
        values["expected_state"] = expected_state

    result = await session.execute(
        update(Nodes)
        .where(Nodes.id == node_id, Nodes.status.in_(from_statuses))
        .values(**values))
    await session.flush()
    return result.rowcount == 1


async def drain_node(session: AsyncSession, node_id: int) -> bool:
    """Transitions the node from running to draining_collectors, the first phase
    of the drain. The node advances to draining on its own once every collector
    has flushed its backlog.

    Also records the intent to take the node offline. The drain is the only signal
    anyone gives that a shutdown is planned, and it has to outlive the status: the
    node ends up stopped either way, whether it was drained first or simply died."""
    return await transition_node_status(
        session, node_id, NODE_STATUS_DRAINING_COLLECTORS, [NODE_STATUS_RUNNING],
        expected_state=NODE_EXPECTED_STATE_OFFLINE)


async def resume_node(session: AsyncSession, node_id: int) -> bool:
    """Transitions the node from any drain phase back to running, and marks it as
    expected to be online again."""
    return await transition_node_status(
        session, node_id, NODE_STATUS_RUNNING,
        [NODE_STATUS_DRAINING_COLLECTORS, NODE_STATUS_DRAINING, NODE_STATUS_DRAINED],
        expected_state=NODE_EXPECTED_STATE_ONLINE)
