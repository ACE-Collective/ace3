"""Tests for 21ef0452ff5a, which rewrites the comments and observable_comments rows stored before every
write normalized its text. The rows are inserted with raw SQL, as the old write paths stored them,
since the models now normalize what they write."""

import hashlib
import importlib.util
from pathlib import Path
from unittest.mock import patch

import pytest
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from sqlalchemy import text

from saq.database.admin import create_superuser_engine
from saq.database.model import Comment, Observable, ObservableComment, User
from saq.database.pool import get_db

MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "alembic" / "ace" / "versions" / "21ef0452ff5a_normalize_comment_line_breaks.py"
)

# stored -> what the upgrade leaves
STORED = {
    "first line\r\nsecond line": "first line\nsecond line",
    "looks benign\r\n": "looks benign",
    "  looks benign": "looks benign",
    "already\nnormal": "already\nnormal",
    "Mixed\r\nline\nbreaks\r\n\r\n": "Mixed\nline\nbreaks",
}


@pytest.fixture
def migration():
    spec = importlib.util.spec_from_file_location("normalize_comment_line_breaks_migration", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def superuser():
    """A connection like the one migrations run on."""
    engine = create_superuser_engine(get_db().get_bind().url.database)
    try:
        with engine.connect() as connection:
            yield connection
    finally:
        engine.dispose()


def _upgrade(migration, connection) -> None:
    with Operations.context(MigrationContext.configure(connection=connection)):
        migration.upgrade()
    connection.commit()


def _user_id() -> int:
    return get_db().query(User).filter(User.username == "unittest").one().id


def _insert_old_comments() -> tuple[list[int], list[int]]:
    """One alert comment and one observable comment per STORED value, as the old write paths stored
    them; returns their ids in STORED's order."""
    db = get_db()
    user_id = _user_id()
    observable = Observable(type="ipv4", sha256=hashlib.sha256(b"10.9.9.9").digest(), value=b"10.9.9.9")
    db.add(observable)
    db.flush()

    comment_ids, observable_comment_ids = [], []
    for stored in STORED:
        comment_ids.append(db.execute(
            text("INSERT INTO comments (user_id, uuid, comment) VALUES (:user_id, 'migration-test', :comment)"),
            {"user_id": user_id, "comment": stored}).lastrowid)
        observable_comment_ids.append(db.execute(
            text("INSERT INTO observable_comments (user_id, observable_id, comment) "
                 "VALUES (:user_id, :observable_id, :comment)"),
            {"user_id": user_id, "observable_id": observable.id, "comment": stored}).lastrowid)

    db.commit()
    return comment_ids, observable_comment_ids


def _texts(model, key, ids: list[int]) -> list[str]:
    db = get_db()
    # a new transaction, which sees what the upgrade committed
    db.commit()
    by_id = dict(db.query(key, model.comment).filter(key.in_(ids)).all())
    return [by_id[i] for i in ids]


@pytest.mark.integration
def test_upgrade_normalizes_stored_comments(migration, superuser):
    comment_ids, observable_comment_ids = _insert_old_comments()
    before = dict(get_db().query(Comment.comment_id, Comment.insert_date).filter(
        Comment.comment_id.in_(comment_ids)).all())

    # a batch smaller than the rows, so the walk crosses batches and a batch of unchanged rows
    with patch.object(migration, "BATCH_SIZE", 2):
        _upgrade(migration, superuser)

    assert _texts(Comment, Comment.comment_id, comment_ids) == list(STORED.values())
    assert _texts(ObservableComment, ObservableComment.id, observable_comment_ids) == list(STORED.values())
    # normalizing the text is not an edit
    rows = get_db().query(Comment).filter(Comment.comment_id.in_(comment_ids)).all()
    assert all(row.edited_at is None for row in rows)
    assert {row.comment_id: row.insert_date for row in rows} == before


@pytest.mark.integration
def test_upgrade_keeps_a_comment_edited_after_it_was_read(migration, superuser):
    """A row whose text changed between the batch's read and its update is left as it now is."""
    comment_ids, _ = _insert_old_comments()
    edited_id = comment_ids[0]
    normalized = migration._normalized
    edits = []

    def edit_then_normalize(comment: str) -> str:
        # runs between the first batch's SELECT and its UPDATE, on a connection of its own; only the
        # case changes, which the column's case-insensitive collation would call equal
        if not edits:
            db = get_db()
            db.execute(text("UPDATE comments SET comment = 'FIRST LINE\r\nSECOND LINE' WHERE comment_id = :id"),
                       {"id": edited_id})
            db.commit()
            edits.append(edited_id)
        return normalized(comment)

    with patch.object(migration, "_normalized", side_effect=edit_then_normalize):
        _upgrade(migration, superuser)

    texts = _texts(Comment, Comment.comment_id, comment_ids)
    assert texts[0] == "FIRST LINE\r\nSECOND LINE"
    assert texts[1:] == list(STORED.values())[1:]
