"""Observable comment service for ACE API v2."""

import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from saq.analysis.observable import Observable as AnalysisObservable
from saq.database.model import Observable as DBObservable, ObservableComment
from saq.database.util.observable_detection import resolve_observable_identity

logger = logging.getLogger(__name__)


async def _find_or_create_observable(
    session: AsyncSession, observable_type: str, observable_value: str
) -> DBObservable:
    """Find an existing DB observable by type+sha256, or create one.

    Raises InvalidDetectionValue if the value is not valid for the type.
    """
    identity = resolve_observable_identity(observable_type, observable_value)
    result = await session.execute(
        select(DBObservable).where(
            DBObservable.type == identity.type,
            DBObservable.sha256 == identity.value_sha256,
        )
    )
    db_observable = result.scalar_one_or_none()
    if db_observable is None:
        db_observable = DBObservable(
            type=identity.type,
            sha256=identity.value_sha256,
            value=identity.value.encode("utf8"),
        )
        session.add(db_observable)
        await session.flush()
    return db_observable


async def get_comments_for_observable(
    session: AsyncSession, observable_id: int
) -> list[ObservableComment]:
    """Get all comments for a specific observable by DB id."""
    result = await session.execute(
        select(ObservableComment)
        .where(ObservableComment.observable_id == observable_id)
        .options(selectinload(ObservableComment.user))
        .order_by(ObservableComment.insert_date)
    )
    return list(result.scalars().all())


async def get_comments_for_observables(
    session: AsyncSession,
    observables: list[AnalysisObservable],
) -> dict[str, list[ObservableComment]]:
    """Bulk load comments for a list of analysis observables.

    Returns a dict keyed by in-memory observable UUID -> list of comments.
    Uses the same type+sha256 matching strategy as observable_detection.py.
    """
    if not observables:
        return {}

    sha256_list = [o.sha256_bytes for o in observables]
    result = await session.execute(
        select(ObservableComment)
        .join(DBObservable, ObservableComment.observable_id == DBObservable.id)
        .where(DBObservable.sha256.in_(sha256_list))
        .options(
            selectinload(ObservableComment.user),
            selectinload(ObservableComment.observable),
        )
        .order_by(ObservableComment.insert_date)
    )
    comments = list(result.scalars().all())

    comments_by_uuid: dict[str, list[ObservableComment]] = {}
    for comment in comments:
        db_obs = comment.observable
        for obs in observables:
            if obs.type == db_obs.type and obs.sha256_bytes == db_obs.sha256:
                comments_by_uuid.setdefault(obs.uuid, []).append(comment)
                break

    return comments_by_uuid


async def get_observable_db_ids(
    session: AsyncSession,
    observables: list[AnalysisObservable],
) -> dict[str, int]:
    """Map in-memory observable UUIDs to their DB ids.

    Returns dict keyed by observable UUID -> DB observable id.
    Only includes observables that already exist in the DB.
    """
    if not observables:
        return {}

    sha256_list = [o.sha256_bytes for o in observables]
    result = await session.execute(
        select(DBObservable).where(DBObservable.sha256.in_(sha256_list))
    )
    db_observables = list(result.scalars().all())

    ids: dict[str, int] = {}
    for db_obs in db_observables:
        for obs in observables:
            if obs.type == db_obs.type and obs.sha256_bytes == db_obs.sha256:
                ids[obs.uuid] = db_obs.id
                break

    return ids


async def create_comment(
    session: AsyncSession,
    user_id: int,
    observable_type: str,
    observable_value: str,
    comment_text: str,
) -> ObservableComment:
    """Create a comment on an observable, creating the DB observable row if needed."""
    db_observable = await _find_or_create_observable(session, observable_type, observable_value)
    comment = ObservableComment(
        user_id=user_id,
        observable_id=db_observable.id,
        comment=comment_text,
    )
    session.add(comment)
    await session.flush()
    await session.refresh(comment)
    await session.refresh(comment, attribute_names=["user"])
    return comment


async def update_comment(
    session: AsyncSession,
    comment_id: int,
    user_id: int,
    comment_text: str,
) -> Optional[ObservableComment]:
    """Update a comment's text. Returns None if not found, raises ValueError if not author."""
    result = await session.execute(
        select(ObservableComment)
        .where(ObservableComment.id == comment_id)
        .options(selectinload(ObservableComment.user))
    )
    comment = result.scalar_one_or_none()
    if comment is None:
        return None
    if comment.user_id != user_id:
        raise PermissionError("Only the comment author can edit this comment")
    comment.comment = comment_text
    await session.flush()
    return comment


async def delete_comment(
    session: AsyncSession,
    comment_id: int,
    user_id: int,
) -> bool:
    """Delete a comment. Returns False if not found, raises ValueError if not author."""
    result = await session.execute(
        select(ObservableComment).where(ObservableComment.id == comment_id)
    )
    comment = result.scalar_one_or_none()
    if comment is None:
        return False
    if comment.user_id != user_id:
        raise PermissionError("Only the comment author can delete this comment")
    await session.delete(comment)
    await session.flush()
    return True
