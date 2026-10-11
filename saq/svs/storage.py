"""How SVS samples hold their bytes in the svs_samples CAS pool, and how they are let go: the
capture holds (saq/svs/capture.py), and the purge of a file deleted from SVS
(saq/svs/actions.py). Kept apart from capture.py, which imports the YARA analysis module, so the
API can use it."""

import logging
from typing import Optional

from sqlalchemy import select

from saq.cas import Hold
from saq.cas.errors import LegalHoldActive, ObjectNotFound
from saq.cas.pool import CASPool
from saq.database.model import SVSSampleDeletion
from saq.database.private_session import private_transaction
from saq.error.reporting import report_exception

# cas_holds.holder_kind of every capture hold; the holder_id is the svs_yara_captures row id, which
# holds both the file and the match record
HOLDER_KIND = "svs_capture"


def capture_hold(capture_id: int) -> Hold:
    return Hold(HOLDER_KIND, str(capture_id))


def release_capture_holds(pool: CASPool, capture_id: int, digests: list[str]) -> None:
    """Releases the capture's hold on each digest. A digest that is gone is not an error (its holds
    went with it), and a release that fails is logged: the object then stays held until a purge."""
    hold = capture_hold(capture_id)
    for digest in digests:
        try:
            pool.release(digest, hold)
        except ObjectNotFound:
            pass
        except Exception as e:
            logging.warning("unable to release svs capture hold %s on %s: %s", hold.holder_id, digest, e)


def is_deleted(sha256: str) -> bool:
    """Whether the file was deleted from SVS (it has a row in svs_sample_deletions)."""
    with private_transaction() as session:
        return session.execute(
            select(SVSSampleDeletion.id).where(SVSSampleDeletion.sha256 == sha256)).first() is not None


def purge_deleted_file(pool: CASPool, sha256: str, *, reason: str, actor: Optional[str]) -> bool:
    """Purges the bytes of a file deleted from SVS, across every hold on them. True when they are
    gone (or were never stored); False, after logging, when they could not be purged (a legal
    hold, a backend failure), so the deletion stays unfinished and can be retried."""
    try:
        pool.purge(sha256, reason=reason, actor=actor)
        return True
    except ObjectNotFound:
        return True
    except LegalHoldActive:
        logging.error("svs sample %s is deleted, but its file is under legal hold and is kept until the hold is released",
                      sha256, extra={"sha256": sha256})
        return False
    except Exception as e:
        logging.error("unable to purge the file of deleted svs sample %s: %s", sha256, e, extra={"sha256": sha256})
        report_exception()
        return False
