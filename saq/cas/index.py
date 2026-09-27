"""Every statement the CAS runs against its index tables (docs/CAS.md, "Data model", "Lifecycle").

Nothing else in ACE writes cas_objects, cas_holds or cas_purges. Every function takes the Session
it should run in; transaction() provides one. Time comparisons (hold expiry, the GC grace cutoff)
happen in the database against NOW(), never against the application clock.

Deletions are never unbounded: callers ask for at most a batch of primary keys at a time, in key
order, and delete those (docs/CAS.md, "Operating constraints").
"""

import secrets
from contextlib import contextmanager
from typing import Iterator, Optional

from sqlalchemy import delete, exists, func, or_, select, text, tuple_, update
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.orm import Session

from saq.cas.errors import CASError
from saq.cas.hold import LEGAL_HOLD_KIND, Hold
from saq.database.model import CASHold, CASObject, CASPurge
from saq.database.pool import get_db

STATE_PRESENT = "present"
STATE_DELETING = "deleting"


@contextmanager
def transaction() -> Iterator[Session]:
    """A private session on the main database's engine, committed on exit and rolled back on
    error. Private on purpose: the thread-shared get_db() session may be mid-transaction in the
    caller (an analysis module, a Flask request), and a CAS commit or rollback must not touch that
    work. Sharing the engine keeps the connection pool's fork handling in force."""
    scoped = get_db()
    if scoped is None:
        raise CASError("the database is not initialized")

    with Session(bind=scoped.get_bind()) as session:
        with session.begin():
            yield session


def _pk(model, pool: str, digest: str):
    return (model.pool == pool) & (model.digest == digest)


def _live_hold():
    return or_(CASHold.expires_at.is_(None), CASHold.expires_at > func.now())


def _cutoff(grace_seconds: int):
    # NOW() - grace, evaluated by the database
    return func.date_sub(func.now(), text(f"INTERVAL {int(grace_seconds)} SECOND"))


#
# objects
#

def insert_object_if_absent(session: Session, pool: str, digest: str, size: int, stored_size: int,
                            key_id: Optional[str]) -> None:
    session.execute(
        mysql_insert(CASObject)
        .values(pool=pool, digest=digest, size=size, stored_size=stored_size, key_id=key_id,
                state=STATE_PRESENT, last_held_at=func.now())
        .prefix_with("IGNORE"))


def lock_object(session: Session, pool: str, digest: str) -> Optional[CASObject]:
    """SELECT ... FOR UPDATE. Holding this is what serializes hold creation against the GC flip."""
    return session.execute(
        select(CASObject).where(_pk(CASObject, pool, digest)).with_for_update()
    ).scalar_one_or_none()


def get_object(session: Session, pool: str, digest: str) -> Optional[CASObject]:
    return session.execute(select(CASObject).where(_pk(CASObject, pool, digest))).scalar_one_or_none()


def touch_last_held(session: Session, pool: str, digest: str) -> None:
    session.execute(
        update(CASObject).where(_pk(CASObject, pool, digest)).values(last_held_at=func.now())
        .execution_options(synchronize_session=False))


def flip_to_deleting(session: Session, pool: str, digest: str, grace_seconds: int) -> bool:
    """The GC's one conditional statement: present -> deleting only if the object is still past its
    grace and nobody holds it. Returns False (zero rows) when a hold arrived after the candidate
    scan, in which case the object is left alone."""
    live = exists().where(_pk(CASHold, pool, digest) & _live_hold())
    result = session.execute(
        update(CASObject)
        .where(_pk(CASObject, pool, digest),
               CASObject.state == STATE_PRESENT,
               CASObject.last_held_at < _cutoff(grace_seconds),
               ~live)
        .values(state=STATE_DELETING)
        .execution_options(synchronize_session=False))
    return result.rowcount == 1


def set_deleting_forced(session: Session, pool: str, digest: str) -> None:
    """purge: deleting regardless of holds (the caller has already checked for a legal hold)."""
    session.execute(
        update(CASObject).where(_pk(CASObject, pool, digest)).values(state=STATE_DELETING)
        .execution_options(synchronize_session=False))


def delete_object_row(session: Session, pool: str, digest: str) -> None:
    """Removes the object row; the foreign key cascade removes its hold rows in the same statement."""
    session.execute(
        delete(CASObject).where(_pk(CASObject, pool, digest)).execution_options(synchronize_session=False))


def gc_candidates(session: Session, pool: str, grace_seconds: int, after_digest: str, limit: int) -> list[str]:
    """Up to limit digests of present, unheld objects past their grace, in primary-key order after
    after_digest (keyset pagination, so a sweep never re-reads what it skipped). The hold check is
    repeated by flip_to_deleting; here it keeps the scan (and a dry run's count) honest."""
    live = exists().where(CASHold.pool == CASObject.pool, CASHold.digest == CASObject.digest, _live_hold())
    return list(session.execute(
        select(CASObject.digest)
        .where(CASObject.pool == pool,
               CASObject.state == STATE_PRESENT,
               CASObject.last_held_at < _cutoff(grace_seconds),
               CASObject.digest > after_digest,
               ~live)
        .order_by(CASObject.digest)
        .limit(limit)
    ).scalars())


def deleting_objects(session: Session, pool: str, limit: int) -> list[str]:
    """Objects a previous GC or purge flipped but did not finish removing."""
    return list(session.execute(
        select(CASObject.digest)
        .where(CASObject.pool == pool, CASObject.state == STATE_DELETING)
        .order_by(CASObject.digest)
        .limit(limit)
    ).scalars())


def digests_present(session: Session, pool: str, digests: list[str]) -> set[str]:
    """Which of the given digests have an index row (any state). The caller batches."""
    if not digests:
        return set()

    return set(session.execute(
        select(CASObject.digest).where(CASObject.pool == pool, CASObject.digest.in_(digests))
    ).scalars())


def sample_objects(session: Session, pool: str, count: int) -> list[CASObject]:
    """Up to count present objects starting from a random point in digest order, wrapping around."""
    start = secrets.token_hex(32)
    base = select(CASObject).where(CASObject.pool == pool, CASObject.state == STATE_PRESENT)
    rows = list(session.execute(
        base.where(CASObject.digest >= start).order_by(CASObject.digest).limit(count)).scalars())
    if len(rows) < count:
        rows.extend(session.execute(
            base.where(CASObject.digest < start).order_by(CASObject.digest).limit(count - len(rows))).scalars())

    return rows


def set_verified(session: Session, pool: str, digest: str) -> None:
    session.execute(
        update(CASObject).where(_pk(CASObject, pool, digest)).values(verified_at=func.now())
        .execution_options(synchronize_session=False))


def pool_summaries(session: Session) -> list[tuple[str, int, int, int]]:
    """(pool, object count, total size, total stored_size) for every pool that has rows, including
    pools that are no longer configured (a renamed pool leaves its rows and bytes behind)."""
    return [tuple(row) for row in session.execute(
        select(CASObject.pool, func.count(), func.coalesce(func.sum(CASObject.size), 0),
               func.coalesce(func.sum(CASObject.stored_size), 0))
        .group_by(CASObject.pool)
        .order_by(CASObject.pool))]


#
# holds
#

def upsert_hold(session: Session, pool: str, digest: str, hold: Hold, created_by: Optional[str]) -> None:
    """Idempotent: a repeated hold is a no-op except that a new expires_at (or created_by) replaces
    the old one, so re-holding extends."""
    stmt = mysql_insert(CASHold).values(
        pool=pool, digest=digest, holder_kind=hold.holder_kind, holder_id=hold.holder_id,
        expires_at=hold.expires_at, created_by=created_by)
    session.execute(stmt.on_duplicate_key_update(
        expires_at=stmt.inserted.expires_at,
        created_by=stmt.inserted.created_by))


def delete_hold(session: Session, pool: str, digest: str, hold: Hold) -> int:
    result = session.execute(
        delete(CASHold)
        .where(_pk(CASHold, pool, digest),
               CASHold.holder_kind == hold.holder_kind,
               CASHold.holder_id == hold.holder_id)
        .execution_options(synchronize_session=False))
    return result.rowcount


def live_hold_exists(session: Session, pool: str, digest: str) -> bool:
    return session.execute(
        select(exists().where(_pk(CASHold, pool, digest) & _live_hold()))).scalar()


def legal_hold_exists(session: Session, pool: str, digest: str) -> bool:
    return session.execute(
        select(exists().where(_pk(CASHold, pool, digest) & (CASHold.holder_kind == LEGAL_HOLD_KIND)))).scalar()


def count_holds(session: Session, pool: str, digest: str) -> int:
    return session.execute(
        select(func.count()).select_from(CASHold).where(_pk(CASHold, pool, digest))).scalar()


def list_holds(session: Session, pool: str, digest: str) -> list[CASHold]:
    return list(session.execute(
        select(CASHold).where(_pk(CASHold, pool, digest))
        .order_by(CASHold.holder_kind, CASHold.holder_id)).scalars())


def delete_expired_holds_batch(session: Session, pool: str, limit: int) -> int:
    """Removes up to limit expired hold rows, chosen in primary-key order. Expired holds on an
    object that still has a live hold would otherwise accumulate (on an object with none they go
    with the row)."""
    keys = list(session.execute(
        select(CASHold.pool, CASHold.digest, CASHold.holder_kind, CASHold.holder_id)
        .where(CASHold.pool == pool, CASHold.expires_at.is_not(None), CASHold.expires_at <= func.now())
        .order_by(CASHold.pool, CASHold.digest, CASHold.holder_kind, CASHold.holder_id)
        .limit(limit)))
    if not keys:
        return 0

    result = session.execute(
        delete(CASHold)
        .where(tuple_(CASHold.pool, CASHold.digest, CASHold.holder_kind, CASHold.holder_id).in_(
            [tuple(key) for key in keys]))
        .execution_options(synchronize_session=False))
    return result.rowcount


#
# purges
#

def insert_purge(session: Session, pool: str, digest: str, reason: str, actor: Optional[str]) -> None:
    session.add(CASPurge(pool=pool, digest=digest, reason=reason, actor=actor))
    session.flush()
