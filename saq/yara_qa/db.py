"""The private database session every yara_qa write runs in."""

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy.orm import Session

from saq.database.pool import get_db


@contextmanager
def transaction() -> Iterator[Session]:
    """A private session on the main database's engine, committed on exit and rolled back on
    error. Private for the same reason as the CAS's (saq/cas/index.py): record_qa_match runs inside
    an analysis module, where the thread-shared get_db() session may be mid-transaction, and a QA
    commit or rollback must not touch that work."""
    scoped = get_db()
    if scoped is None:
        raise RuntimeError("the database is not initialized")

    with Session(bind=scoped.get_bind()) as session:
        with session.begin():
            yield session
