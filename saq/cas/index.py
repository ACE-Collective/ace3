"""Every statement the CAS runs against its index tables (docs/CAS.md, "Data model", "Lifecycle").

Nothing else in ACE writes cas_objects, cas_holds, cas_purges or cas_touches. Every function takes
the Session it should run in; transaction(database) provides one, and the session carries which
chain's copy of the tables it runs against (a pool's index_database). Time comparisons (hold
expiry, the GC grace cutoff, the ttl window) happen in the database against NOW(), never against
the application clock.

Deletions are never unbounded: callers ask for at most a batch of primary keys at a time, in key
order, and delete those (docs/CAS.md, "Operating constraints").
"""

import secrets
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Optional

from sqlalchemy import case, delete, exists, func, or_, select, text, tuple_, update
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.orm import Session

from saq.cas.errors import CASError
from saq.cas.hold import LEGAL_HOLD_KIND, Hold
from saq.constants import DB_ACE, DB_EMAIL_ARCHIVE
from saq.database.model import (
    CASHold,
    CASObject,
    CASPurge,
    EmailArchiveCASHold,
    EmailArchiveCASObject,
    EmailArchiveCASPurge,
    EmailArchiveCASTouch,
)
from saq.database.pool import get_db

STATE_PRESENT = "present"
STATE_DELETING = "deleting"


@dataclass(frozen=True)
class IndexTables:
    """One chain's copy of the index tables."""
    object: type
    hold: type
    purge: type
    touch: Optional[type]       # cas_touches, only in a chain that ttl pools can use


# index_database (CASPoolConfig) -> its tables
TABLES = {
    DB_ACE: IndexTables(CASObject, CASHold, CASPurge, None),
    DB_EMAIL_ARCHIVE: IndexTables(EmailArchiveCASObject, EmailArchiveCASHold, EmailArchiveCASPurge, EmailArchiveCASTouch),
}

_TABLES_KEY = "cas_index_tables"


@contextmanager
def transaction(database: str = DB_ACE) -> Iterator[Session]:
    """A private session on the named database's engine, committed on exit and rolled back on
    error. Private on purpose: the thread-shared get_db() session may be mid-transaction in the
    caller (an analysis module, a Flask request), and a CAS commit or rollback must not touch that
    work. Sharing the engine keeps the connection pool's fork handling in force."""
    tables = TABLES[database]
    scoped = get_db(database)
    if scoped is None:
        raise CASError("the database is not initialized")

    with Session(bind=scoped.get_bind()) as session:
        session.info[_TABLES_KEY] = tables
        with session.begin():
            yield session


def _t(session: Session) -> IndexTables:
    return session.info[_TABLES_KEY]


def _pk(model, pool: str, digest: str):
    return (model.pool == pool) & (model.digest == digest)


def _live_hold(hold_table):
    return or_(hold_table.expires_at.is_(None), hold_table.expires_at > func.now())


def _cutoff(grace_seconds: int):
    # NOW() - grace, evaluated by the database
    return func.date_sub(func.now(), text(f"INTERVAL {int(grace_seconds)} SECOND"))


def _gc_eligible(t: IndexTables, older_than_seconds: int, touched_within_days: Optional[int]) -> list:
    """What makes an object collectable, given an outer reference to t.object: present, last held
    (or put) longer ago than older_than_seconds, no live hold, and for a ttl pool no touch within
    touched_within_days. The age test is what lets the scan use i_cas_objects_gc. While put() is the
    only thing that touches, it also bumps last_held_at, so the touch test decides nothing; it is for
    the read-side touch the analysis cache will add (docs/CAS.md, "Lifecycle")."""
    o, h = t.object, t.hold
    conditions = [
        o.state == STATE_PRESENT,
        o.last_held_at < _cutoff(older_than_seconds),
        ~exists().where(h.pool == o.pool, h.digest == o.digest, _live_hold(h)),
    ]
    if touched_within_days is not None:
        touch = t.touch
        conditions.append(~exists().where(
            touch.pool == o.pool, touch.digest == o.digest,
            touch.day >= func.date_sub(func.curdate(), text(f"INTERVAL {int(touched_within_days)} DAY"))))

    return conditions


#
# objects
#

def insert_object_if_absent(session: Session, pool: str, digest: str, size: int, stored_size: int,
                            key_id: Optional[str]) -> None:
    """Insert the object row unless it exists, and leave it exclusively locked either way (an
    existing row keeps its columns: the update is a no-op).

    Not INSERT IGNORE: on a duplicate key that takes a *shared* lock on the existing row, and two
    puts of one digest that both go on to lock_object() (FOR UPDATE) deadlock upgrading it. ON
    DUPLICATE KEY UPDATE takes an exclusive record lock on a duplicate primary key straight away,
    so concurrent puts of one digest queue on the row instead."""
    o = _t(session).object
    stmt = mysql_insert(o).values(
        pool=pool, digest=digest, size=size, stored_size=stored_size, key_id=key_id,
        state=STATE_PRESENT, last_held_at=func.now())
    session.execute(stmt.on_duplicate_key_update(digest=o.digest))


def lock_object(session: Session, pool: str, digest: str):
    """SELECT ... FOR UPDATE. Holding this is what serializes hold creation against the GC flip."""
    o = _t(session).object
    return session.execute(select(o).where(_pk(o, pool, digest)).with_for_update()).scalar_one_or_none()


def get_object(session: Session, pool: str, digest: str):
    o = _t(session).object
    return session.execute(select(o).where(_pk(o, pool, digest))).scalar_one_or_none()


def touch_last_held(session: Session, pool: str, digest: str) -> None:
    o = _t(session).object
    session.execute(
        update(o).where(_pk(o, pool, digest)).values(last_held_at=func.now())
        .execution_options(synchronize_session=False))


def record_touch(session: Session, pool: str, digest: str) -> None:
    """A ttl pool's use of an object today. Append-only: INSERT IGNORE, so the second use on a day
    changes nothing and no shared row is ever updated."""
    touch = _t(session).touch
    if touch is None:
        raise CASError(f"cas pool {pool} is ttl but its index database has no cas_touches table")

    session.execute(mysql_insert(touch).prefix_with("IGNORE").values(day=func.curdate(), pool=pool, digest=digest))


def flip_to_deleting(session: Session, pool: str, digest: str, older_than_seconds: int,
                     touched_within_days: Optional[int] = None) -> bool:
    """The GC's one conditional statement: present -> deleting only if the object is still
    collectable (_gc_eligible). Returns False (zero rows) when a hold or a put arrived after the
    candidate scan, in which case the object is left alone."""
    t = _t(session)
    o = t.object
    result = session.execute(
        update(o)
        .where(_pk(o, pool, digest), *_gc_eligible(t, older_than_seconds, touched_within_days))
        .values(state=STATE_DELETING)
        .execution_options(synchronize_session=False))
    return result.rowcount == 1


def set_deleting_forced(session: Session, pool: str, digest: str) -> None:
    """purge: deleting regardless of holds (the caller has already checked for a legal hold)."""
    o = _t(session).object
    session.execute(
        update(o).where(_pk(o, pool, digest)).values(state=STATE_DELETING)
        .execution_options(synchronize_session=False))


def delete_object_row(session: Session, pool: str, digest: str) -> None:
    """Removes the object row; the foreign key cascade removes its hold rows in the same statement.
    A ttl object's touches stay until their partition is dropped: a touch without an object is
    harmless, and a put that recreates the object finds them."""
    o = _t(session).object
    session.execute(delete(o).where(_pk(o, pool, digest)).execution_options(synchronize_session=False))


def gc_candidates(session: Session, pool: str, older_than_seconds: int, after_digest: str, limit: int,
                  touched_within_days: Optional[int] = None) -> list[str]:
    """Up to limit digests of collectable objects (_gc_eligible), in primary-key order after
    after_digest (keyset pagination, so a sweep never re-reads what it skipped). flip_to_deleting
    repeats the check; here it keeps the scan (and a dry run's count) honest."""
    t = _t(session)
    o = t.object
    return list(session.execute(
        select(o.digest)
        .where(o.pool == pool, o.digest > after_digest, *_gc_eligible(t, older_than_seconds, touched_within_days))
        .order_by(o.digest)
        .limit(limit)
    ).scalars())


def deleting_objects(session: Session, pool: str, limit: int) -> list[str]:
    """Objects a previous GC or purge flipped but did not finish removing."""
    o = _t(session).object
    return list(session.execute(
        select(o.digest)
        .where(o.pool == pool, o.state == STATE_DELETING)
        .order_by(o.digest)
        .limit(limit)
    ).scalars())


def digests_present(session: Session, pool: str, digests: list[str]) -> set[str]:
    """Which of the given digests have an index row (any state). The caller batches."""
    if not digests:
        return set()

    o = _t(session).object
    return set(session.execute(select(o.digest).where(o.pool == pool, o.digest.in_(digests))).scalars())


def sample_objects(session: Session, pool: str, count: int) -> list:
    """Up to count present objects starting from a random point in digest order, wrapping around."""
    o = _t(session).object
    start = secrets.token_hex(32)
    base = select(o).where(o.pool == pool, o.state == STATE_PRESENT)
    rows = list(session.execute(base.where(o.digest >= start).order_by(o.digest).limit(count)).scalars())
    if len(rows) < count:
        rows.extend(session.execute(
            base.where(o.digest < start).order_by(o.digest).limit(count - len(rows))).scalars())

    return rows


def set_verified(session: Session, pool: str, digest: str) -> None:
    o = _t(session).object
    session.execute(
        update(o).where(_pk(o, pool, digest)).values(verified_at=func.now())
        .execution_options(synchronize_session=False))


def pool_summaries(session: Session) -> list[tuple[str, int, int, int]]:
    """(pool, object count, total size, total stored_size) for every pool that has rows in this
    session's database, including pools that are no longer configured (a renamed pool leaves its
    rows and bytes behind)."""
    o = _t(session).object
    return [tuple(row) for row in session.execute(
        select(o.pool, func.count(), func.coalesce(func.sum(o.size), 0), func.coalesce(func.sum(o.stored_size), 0))
        .group_by(o.pool)
        .order_by(o.pool))]


#
# health (read-only aggregates for the cas.pool monitor, saq/cas/health.py)
#
# object_summaries is one grouped scan of cas_objects, which is cheap at the size of a held pool and
# is not run against ttl pools (health.py reports their counts from the cheaper queries below).
#

def object_summaries(session: Session, verified_within_seconds: int, pools: Optional[list[str]] = None) -> list[tuple]:
    """(pool, state, count, total size, total stored_size, never verified, verified within
    verified_within_seconds) per pool and state, for the given pools (default: every pool)."""
    o = _t(session).object
    query = (
        select(o.pool, o.state, func.count(),
               func.coalesce(func.sum(o.size), 0),
               func.coalesce(func.sum(o.stored_size), 0),
               func.coalesce(func.sum(case((o.verified_at.is_(None), 1), else_=0)), 0),
               func.coalesce(func.sum(case((o.verified_at >= _cutoff(verified_within_seconds), 1), else_=0)), 0))
        .group_by(o.pool, o.state)
        .order_by(o.pool, o.state))
    if pools is not None:
        query = query.where(o.pool.in_(pools))

    return [tuple(row) for row in session.execute(query)]


def count_deleting(session: Session, pool: str) -> int:
    """Objects in deleting: a range scan of i_cas_objects_gc, cheap however large the pool is."""
    o = _t(session).object
    return session.execute(
        select(func.count()).select_from(o).where(o.pool == pool, o.state == STATE_DELETING)).scalar()


def hold_summaries(session: Session) -> list[tuple]:
    """(pool, live holds, expired holds, legal holds, objects with at least one live hold) per pool."""
    h = _t(session).hold
    live = _live_hold(h)
    return [tuple(row) for row in session.execute(
        select(h.pool,
               func.coalesce(func.sum(case((live, 1), else_=0)), 0),
               func.coalesce(func.sum(case((live, 0), else_=1)), 0),
               func.coalesce(func.sum(case((h.holder_kind == LEGAL_HOLD_KIND, 1), else_=0)), 0),
               func.count(func.distinct(case((live, h.digest), else_=None))))
        .group_by(h.pool)
        .order_by(h.pool))]


def count_gc_candidates(session: Session, pool: str, older_than_seconds: int,
                        touched_within_days: Optional[int] = None) -> int:
    """How many objects gc_candidates would return with these arguments."""
    t = _t(session)
    o = t.object
    return session.execute(
        select(func.count()).select_from(o)
        .where(o.pool == pool, *_gc_eligible(t, older_than_seconds, touched_within_days))).scalar()


def purge_counts_since(session: Session, seconds: int) -> dict[str, int]:
    """Purges per pool within the last seconds."""
    p = _t(session).purge
    return {pool: count for pool, count in session.execute(
        select(p.pool, func.count()).where(p.purged_at >= _cutoff(seconds)).group_by(p.pool))}


#
# holds
#

def upsert_hold(session: Session, pool: str, digest: str, hold: Hold, created_by: Optional[str]) -> None:
    """Idempotent: a repeated hold is a no-op except that a new expires_at (or created_by) replaces
    the old one, so re-holding extends."""
    h = _t(session).hold
    stmt = mysql_insert(h).values(
        pool=pool, digest=digest, holder_kind=hold.holder_kind, holder_id=hold.holder_id,
        expires_at=hold.expires_at, created_by=created_by)
    session.execute(stmt.on_duplicate_key_update(
        expires_at=stmt.inserted.expires_at,
        created_by=stmt.inserted.created_by))


def delete_hold(session: Session, pool: str, digest: str, hold: Hold) -> int:
    h = _t(session).hold
    result = session.execute(
        delete(h)
        .where(_pk(h, pool, digest), h.holder_kind == hold.holder_kind, h.holder_id == hold.holder_id)
        .execution_options(synchronize_session=False))
    return result.rowcount


def live_hold_exists(session: Session, pool: str, digest: str) -> bool:
    h = _t(session).hold
    return session.execute(select(exists().where(_pk(h, pool, digest) & _live_hold(h)))).scalar()


def legal_hold_exists(session: Session, pool: str, digest: str) -> bool:
    h = _t(session).hold
    return session.execute(
        select(exists().where(_pk(h, pool, digest) & (h.holder_kind == LEGAL_HOLD_KIND)))).scalar()


def count_holds(session: Session, pool: str, digest: str) -> int:
    h = _t(session).hold
    return session.execute(select(func.count()).select_from(h).where(_pk(h, pool, digest))).scalar()


def list_holds(session: Session, pool: str, digest: str) -> list:
    h = _t(session).hold
    return list(session.execute(
        select(h).where(_pk(h, pool, digest)).order_by(h.holder_kind, h.holder_id)).scalars())


def delete_expired_holds_batch(session: Session, pool: str, limit: int) -> int:
    """Removes up to limit expired hold rows, chosen in primary-key order. Expired holds on an
    object that still has a live hold would otherwise accumulate (on an object with none they go
    with the row)."""
    h = _t(session).hold
    keys = list(session.execute(
        select(h.pool, h.digest, h.holder_kind, h.holder_id)
        .where(h.pool == pool, h.expires_at.is_not(None), h.expires_at <= func.now())
        .order_by(h.pool, h.digest, h.holder_kind, h.holder_id)
        .limit(limit)))
    if not keys:
        return 0

    result = session.execute(
        delete(h)
        .where(tuple_(h.pool, h.digest, h.holder_kind, h.holder_id).in_([tuple(key) for key in keys]))
        .execution_options(synchronize_session=False))
    return result.rowcount


#
# purges
#

def insert_purge(session: Session, pool: str, digest: str, reason: str, actor: Optional[str]) -> None:
    session.add(_t(session).purge(pool=pool, digest=digest, reason=reason, actor=actor))
    session.flush()
