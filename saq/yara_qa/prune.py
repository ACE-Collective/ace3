"""Removing expired YARA QA matches (docs/YARA_QA.md).

A match expires yara_qa.retention_days after its file last matched. prune_expired() removes expired
rows in batches of primary keys, one short transaction per batch and never one unbounded DELETE
(docs/CAS.md, "Operating constraints"), gives their slots back, and then releases their CAS holds.
The CAS GC reclaims the bytes once the pool's grace period has passed.

Rows are selected FOR UPDATE SKIP LOCKED, so a prune never waits on an engine worker that is
renewing a match at that moment, and a renewal that lands first moves expires_at out of the batch.
"""

import logging
import time
from dataclasses import dataclass

from sqlalchemy import func, select

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


def _expired():
    return YaraQAMatch.expires_at < func.now()


def prune_expired(*, dry_run: bool = False) -> PruneStats:
    config = get_config().yara_qa
    stats = PruneStats(dry_run=dry_run)

    if dry_run:
        with private_transaction() as session:
            stats.expired = session.execute(select(func.count()).select_from(YaraQAMatch).where(_expired())).scalar_one()

        return stats

    pool = get_cas().pool(config.pool)
    while True:
        with private_transaction() as session:
            rows = session.execute(
                select(YaraQAMatch.id, YaraQAMatch.signature_uuid, YaraQAMatch.signature_version,
                       YaraQAMatch.sha256, YaraQAMatch.match_digest, YaraQAMatch.expires_at)
                .where(_expired())
                .order_by(YaraQAMatch.expires_at, YaraQAMatch.id)
                .limit(config.prune_batch_size)
                .with_for_update(skip_locked=True)).all()

            matches = [MatchRef.from_row(row) for row in rows]
            delete_match_rows(session, matches)

        if not matches:
            break

        stats.batches += 1
        stats.expired += len(matches)
        stats.deleted += len(matches)

        # after the commit: a match is gone from the index before its bytes can go
        for match in matches:
            if not release_match_holds(pool, match):
                stats.release_failures += 1

        if len(matches) < config.prune_batch_size:
            break

        if config.prune_batch_pause_seconds:
            time.sleep(config.prune_batch_pause_seconds)

    logging.info("yara qa prune removed %s expired matches in %s batches (%s hold releases failed)",
                 stats.deleted, stats.batches, stats.release_failures)
    return stats
