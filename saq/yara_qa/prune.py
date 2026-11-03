"""Removing YARA QA matches: the expired ones, daily, and the ones an analyst purges (docs/YARA_QA.md).

A match expires yara_qa.retention_days after its file last matched. prune_expired() removes expired
rows, and purge_matches() the rows an analyst chose, in batches of primary keys, one short
transaction per batch and never one unbounded DELETE (docs/CAS.md, "Operating constraints"). Both
give the rows' slots back and then release their CAS holds. The CAS GC reclaims the bytes once the
pool's grace period has passed and no other hold remains.

Rows are selected FOR UPDATE SKIP LOCKED, so neither waits on a yara qa recorder that is renewing a
match at that moment, and a renewal that lands first moves expires_at out of a prune's batch.
"""

import logging
import time
from dataclasses import dataclass
from typing import Optional

from sqlalchemy import ColumnElement, func, select

from saq.cas import get_cas
from saq.configuration.config import get_config
from saq.database.model import YaraQAMatch
from saq.database.private_session import private_transaction
from saq.yara_qa.store import MatchRef, delete_match_rows, release_match_holds


@dataclass
class PruneStats:
    dry_run: bool
    expired: int = 0
    deleted: int = 0
    batches: int = 0
    release_failures: int = 0


@dataclass
class PurgeStats:
    deleted: int = 0
    # rows another transaction held while the purge ran: purging again removes them
    remaining: int = 0
    batches: int = 0
    release_failures: int = 0


def _expired():
    return YaraQAMatch.expires_at < func.now()


def _remove_matches(conditions: list[ColumnElement[bool]], order_by: list, stats) -> None:
    """Removes the rows matching conditions, counting into stats (deleted, batches,
    release_failures)."""
    config = get_config().yara_qa
    pool = get_cas().pool(config.pool)
    while True:
        with private_transaction() as session:
            rows = session.execute(
                select(YaraQAMatch.id, YaraQAMatch.signature_uuid, YaraQAMatch.signature_version,
                       YaraQAMatch.sha256, YaraQAMatch.match_digest, YaraQAMatch.expires_at)
                .where(*conditions)
                .order_by(*order_by)
                .limit(config.prune_batch_size)
                .with_for_update(skip_locked=True)).all()

            matches = [MatchRef.from_row(row) for row in rows]
            delete_match_rows(session, matches)

        if not matches:
            break

        stats.batches += 1
        stats.deleted += len(matches)

        # after the commit: a match is gone from the index before its bytes can go
        for match in matches:
            if not release_match_holds(pool, match):
                stats.release_failures += 1

        if len(matches) < config.prune_batch_size:
            break

        if config.prune_batch_pause_seconds:
            time.sleep(config.prune_batch_pause_seconds)


def prune_expired(*, dry_run: bool = False) -> PruneStats:
    stats = PruneStats(dry_run=dry_run)

    if dry_run:
        with private_transaction() as session:
            stats.expired = session.execute(select(func.count()).select_from(YaraQAMatch).where(_expired())).scalar_one()

        return stats

    _remove_matches([_expired()], [YaraQAMatch.expires_at, YaraQAMatch.id], stats)
    stats.expired = stats.deleted

    logging.info("yara qa prune removed %s expired matches in %s batches (%s hold releases failed)",
                 stats.deleted, stats.batches, stats.release_failures)
    return stats


def purge_matches(signature_uuid: str, *, versions: Optional[list[str]] = None,
                  match_ids: Optional[list[int]] = None) -> PurgeStats:
    """Removes stored files of one signature: those of the given versions, or the given matches.
    Exactly one of versions and match_ids. A match id of another signature is not removed. Rows
    whose puts are still in flight (no match_digest yet) are left to the recorder storing them."""
    if (versions is None) == (match_ids is None):
        raise ValueError("purge_matches needs versions or match_ids, not both")

    conditions = [YaraQAMatch.signature_uuid == signature_uuid, YaraQAMatch.match_digest.is_not(None)]
    if versions is not None:
        conditions.append(YaraQAMatch.signature_version.in_(versions))
    else:
        conditions.append(YaraQAMatch.id.in_(match_ids))

    stats = PurgeStats()
    if versions == [] or match_ids == []:
        return stats

    _remove_matches(conditions, [YaraQAMatch.id], stats)

    with private_transaction() as session:
        stats.remaining = session.execute(select(func.count()).select_from(YaraQAMatch).where(*conditions)).scalar_one()

    logging.info("purged %s yara qa matches of signature %s (%s left held by another transaction, %s hold releases failed)",
                 stats.deleted, signature_uuid, stats.remaining, stats.release_failures,
                 extra={"signature_uuid": signature_uuid})
    return stats
