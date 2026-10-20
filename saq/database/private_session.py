"""A database transaction of its own, for code that must not share the caller's session."""

import logging
import random
import time
from contextlib import contextmanager
from typing import Callable, Iterator, Optional, TypeVar

from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from saq.database.pool import get_db
from saq.database.retry import get_dbapi_error_code
from saq.shutdown import is_shutting_down

T = TypeVar("T")

# the MySQL errors that roll a transaction back for reasons of timing rather than content, so the
# same transaction may well succeed when run again: 1205 lock wait timeout, 1213 deadlock victim
RETRYABLE_LOCK_ERROR_CODES = frozenset({1205, 1213})


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


def run_private_transaction(work: Callable[..., T], *args, attempts: int = 5, description: str = "transaction",
                            extra: Optional[dict] = None, **kwargs) -> T:
    """Runs work(session, *args, **kwargs) in a private_transaction and returns what it returns.
    When MySQL rolls the transaction back as a deadlock victim (1213) or a lock wait times out
    (1205), the whole transaction runs again, in a new private_transaction, up to attempts times
    in all; any other error, the last failed attempt, and a failure while the process is shutting
    down are raised unchanged. Each retry is logged at WARNING with the description and extra.

    The retry boundary is the transaction: MySQL has already undone everything the failed attempt
    wrote, so work starts over from nothing. work must therefore have no effects outside the
    transaction (logging what it wrote, files, CAS puts, state it keeps across calls): a retried
    attempt would repeat them. Return what changed and act on it after this returns. Taking locks
    in a consistent order is still what prevents a deadlock; this is the backstop."""
    if attempts < 1:
        raise ValueError(f"attempts must be at least 1, not {attempts}")

    for attempt in range(1, attempts + 1):
        try:
            with private_transaction() as session:
                return work(session, *args, **kwargs)
        except DBAPIError as e:
            code = get_dbapi_error_code(e)
            if code not in RETRYABLE_LOCK_ERROR_CODES or attempt == attempts or is_shutting_down():
                raise

            logging.warning("%s rolled back (%s): %s; trying again (attempt %d of %d)", description, code, e.orig,
                            attempt + 1, attempts, extra={**(extra or {}), "error_code": code})
            # jittered so two victims of one deadlock do not meet again in lockstep
            time.sleep(random.uniform(0, 0.05 * 2 ** attempt))
