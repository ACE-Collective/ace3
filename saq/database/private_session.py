"""A database transaction of its own, for code that must not share the caller's session."""

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy.orm import Session

from saq.database.pool import get_db


@contextmanager
def private_transaction() -> Iterator[Session]:
    """A private session on the main database's engine, committed on exit and rolled back on
    error. Private because the thread-shared get_db() session of the calling process (an analysis
    module, a Flask request, a service loop) may be mid-transaction, and this commit or rollback
    must not touch that work. Sharing the engine keeps the connection pool's fork handling in
    force. The CAS keeps its own equivalent (saq/cas/index.py)."""
    scoped = get_db()
    if scoped is None:
        raise RuntimeError("the database is not initialized")

    with Session(bind=scoped.get_bind()) as session:
        with session.begin():
            yield session
