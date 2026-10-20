"""Comments on a test run (docs/SVS_RUNS.md, *Reviewing runs*): anyone who manages runs adds one;
only its author changes or deletes it. Each change is an AUDIT record. svs_run_comments is written
here only."""

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import select

from saq.database.model import SVSRunComment
from saq.database.pool import get_db
from saq.svs.run_events import run_log_fields
from saq.svs.runs import get_run

# a comment is text a person types, not a document
MAX_COMMENT_LENGTH = 16384


class UnknownComment(LookupError):
    pass


class NotTheAuthor(PermissionError):
    pass


class InvalidComment(ValueError):
    pass


def _text(comment: str) -> str:
    comment = (comment or "").replace("\r\n", "\n").strip()
    if not comment:
        raise InvalidComment("a comment can't be empty")
    if len(comment) > MAX_COMMENT_LENGTH:
        raise InvalidComment(f"a comment is at most {MAX_COMMENT_LENGTH} characters")
    return comment


def list_comments(run_uuid: str) -> list[SVSRunComment]:
    """The run's comments, oldest first. Raises UnknownRun."""
    run = get_run(run_uuid)
    return list(get_db().execute(
        select(SVSRunComment).where(SVSRunComment.run_id == run.id).order_by(SVSRunComment.id)).scalars())


def add_comment(run_uuid: str, user_id: int, actor: str, comment: str, now: Optional[datetime] = None) -> SVSRunComment:
    """Raises UnknownRun, InvalidComment."""
    run = get_run(run_uuid)
    row = SVSRunComment(run_id=run.id, user_id=user_id, comment=_text(comment), created_at=now or datetime.now())
    db = get_db()
    db.add(row)
    db.commit()
    db.refresh(row)
    logging.info("AUDIT: svs run comment added", extra={**run_log_fields(run), "comment_id": row.id, "actor": actor,
                                                        "actor_user_id": user_id})
    return row


def _own_comment(run_uuid: str, comment_id: int, user_id: int):
    run = get_run(run_uuid)
    row = get_db().execute(select(SVSRunComment).where(
        SVSRunComment.id == comment_id, SVSRunComment.run_id == run.id)).scalar_one_or_none()
    if row is None:
        raise UnknownComment(f"comment {comment_id} not found on run {run.uuid}")
    if row.user_id != user_id:
        raise NotTheAuthor("only its author changes or deletes a comment")
    return run, row


def update_comment(run_uuid: str, comment_id: int, user_id: int, actor: str, comment: str) -> SVSRunComment:
    """Raises UnknownRun, UnknownComment, NotTheAuthor, InvalidComment."""
    run, row = _own_comment(run_uuid, comment_id, user_id)
    row.comment = _text(comment)
    db = get_db()
    db.commit()
    db.refresh(row)
    logging.info("AUDIT: svs run comment changed", extra={**run_log_fields(run), "comment_id": row.id, "actor": actor,
                                                          "actor_user_id": user_id})
    return row


def delete_comment(run_uuid: str, comment_id: int, user_id: int, actor: str) -> None:
    """Raises UnknownRun, UnknownComment, NotTheAuthor."""
    run, row = _own_comment(run_uuid, comment_id, user_id)
    db = get_db()
    db.delete(row)
    db.commit()
    logging.info("AUDIT: svs run comment deleted", extra={**run_log_fields(run), "comment_id": comment_id,
                                                          "actor": actor, "actor_user_id": user_id})
