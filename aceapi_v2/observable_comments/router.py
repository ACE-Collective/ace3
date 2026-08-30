"""Observable comment router for ACE API v2."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Security
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import get_current_auth, require_permission
from aceapi_v2.observable_comments import service
from aceapi_v2.observable_comments.schemas import (
    ObservableCommentCreate,
    ObservableCommentRead,
    ObservableCommentUpdate,
)
from aceapi_v2.schemas import ListResponse
from saq.database.util.observable_detection import InvalidDetectionValue

router = APIRouter(dependencies=[Security(get_current_auth)])


def _to_read(comment) -> ObservableCommentRead:
    return ObservableCommentRead(
        id=comment.id,
        insert_date=comment.insert_date,
        user_id=comment.user_id,
        user_display_name=comment.user.display_name if comment.user else "unknown",
        observable_id=comment.observable_id,
        comment=comment.comment,
    )


@router.get("/{observable_id}", response_model=ListResponse[ObservableCommentRead])
async def list_comments(
    observable_id: int,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _: Annotated[ApiAuthResult, Depends(require_permission("observable", "read"))],
) -> ListResponse[ObservableCommentRead]:
    comments = await service.get_comments_for_observable(session, observable_id)
    return ListResponse(data=[_to_read(c) for c in comments])


@router.post("/", response_model=ObservableCommentRead, status_code=201)
async def create_comment(
    body: ObservableCommentCreate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("observable", "write"))],
) -> ObservableCommentRead:
    if auth.auth_user_id is None:
        raise HTTPException(status_code=401, detail="User authentication required")
    try:
        comment = await service.create_comment(
            session, auth.auth_user_id, body.observable_type, body.observable_value, body.comment
        )
    except InvalidDetectionValue as e:
        raise HTTPException(status_code=400, detail=str(e))
    return _to_read(comment)


@router.patch("/{comment_id}", response_model=ObservableCommentRead)
async def update_comment(
    comment_id: int,
    body: ObservableCommentUpdate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("observable", "write"))],
) -> ObservableCommentRead:
    if auth.auth_user_id is None:
        raise HTTPException(status_code=401, detail="User authentication required")
    try:
        comment = await service.update_comment(session, comment_id, auth.auth_user_id, body.comment)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Only the comment author can edit this comment")
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")
    return _to_read(comment)


@router.delete("/{comment_id}", status_code=204)
async def delete_comment(
    comment_id: int,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    auth: Annotated[ApiAuthResult, Depends(require_permission("observable", "write"))],
) -> None:
    if auth.auth_user_id is None:
        raise HTTPException(status_code=401, detail="User authentication required")
    try:
        deleted = await service.delete_comment(session, comment_id, auth.auth_user_id)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Only the comment author can delete this comment")
    if not deleted:
        raise HTTPException(status_code=404, detail="Comment not found")
