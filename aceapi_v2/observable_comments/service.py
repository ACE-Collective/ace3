"""Observable comment service for ACE API v2."""

import logging
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from aceapi_v2.auth.schemas import ApiAuthResult
from saq.analysis.observable import Observable as AnalysisObservable
from saq.database.model import Observable as DBObservable, ObservableComment, normalize_comment
from saq.database.util.observable_detection import (
    resolve_observable_identity,
    validate_observable_type,
)
from saq.logging import log_audit

logger = logging.getLogger(__name__)


async def _find_or_create_observable(
    session: AsyncSession, observable_type: str, observable_value: str
) -> DBObservable:
    """Find an existing DB observable by type+sha256, or create one.

    Raises InvalidDetectionValue if the type is not in the registry, or the value is not valid for
    the type. This path can INSERT into the shared observables table, so the type must be one a
    picker can produce and filter.
    """
    validate_observable_type(observable_type)
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


def _observable_fields(db_observable: DBObservable) -> dict:
    """The extra={} fields naming the observable a comment is on, as the observables table stores it."""
    return {
        "observable_id": db_observable.id,
        "observable_type": db_observable.type,
        "observable_value": db_observable.value.decode("utf8", errors="replace"),
    }


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
    auth: ApiAuthResult,
    observable_type: str,
    observable_value: str,
    comment_text: str,
    **audit_fields,
) -> ObservableComment:
    """Create auth's comment on an observable, creating the DB observable row if needed.
    audit_fields go into the audit record's extra={} along with the comment's own fields."""
    db_observable = await _find_or_create_observable(session, observable_type, observable_value)
    comment = ObservableComment(
        user_id=auth.auth_user_id,
        observable_id=db_observable.id,
        comment=comment_text,
    )
    session.add(comment)
    await session.flush()
    await session.refresh(comment)
    await session.refresh(comment, attribute_names=["user"])
    fields = _observable_fields(db_observable)
    log_audit("user %s added comment %s to observable %s %s", auth.auth_name, comment.comment,
              fields["observable_type"], fields["observable_value"],
              auth=auth, comment_id=comment.id, **fields, **audit_fields)
    return comment


async def update_comment(
    session: AsyncSession,
    comment_id: int,
    auth: ApiAuthResult,
    comment_text: str,
) -> Optional[ObservableComment]:
    """Update auth's comment's text. Returns None if not found, raises PermissionError if auth is not its author."""
    result = await session.execute(
        select(ObservableComment)
        .where(ObservableComment.id == comment_id)
        .options(selectinload(ObservableComment.user), selectinload(ObservableComment.observable))
    )
    comment = result.scalar_one_or_none()
    if comment is None:
        return None
    if comment.user_id != auth.auth_user_id:
        raise PermissionError("Only the comment author can edit this comment")
    # stored comments are normalized, so text that normalizes to the stored text is not a change and
    # must not mark it edited
    comment_text = normalize_comment(comment_text)
    if comment.comment != comment_text:
        fields = _observable_fields(comment.observable)
        log_audit("user %s edited comment %s on observable %s %s from %r to %r", auth.auth_name, comment_id,
                  fields["observable_type"], fields["observable_value"], comment.comment, comment_text,
                  auth=auth, comment_id=comment_id, **fields)
        comment.comment = comment_text
        comment.edited_at = func.now()
        await session.flush()
        await session.refresh(comment, attribute_names=["edited_at"])
    return comment


async def delete_comment(
    session: AsyncSession,
    comment_id: int,
    auth: ApiAuthResult,
) -> bool:
    """Delete auth's comment. Returns False if not found, raises PermissionError if auth is not its author."""
    result = await session.execute(
        select(ObservableComment)
        .where(ObservableComment.id == comment_id)
        .options(selectinload(ObservableComment.observable))
    )
    comment = result.scalar_one_or_none()
    if comment is None:
        return False
    if comment.user_id != auth.auth_user_id:
        raise PermissionError("Only the comment author can delete this comment")
    fields = _observable_fields(comment.observable)
    log_audit("user %s deleted comment %s from observable %s %s", auth.auth_name, comment.comment,
              fields["observable_type"], fields["observable_value"], auth=auth, comment_id=comment_id, **fields)
    await session.delete(comment)
    await session.flush()
    return True
