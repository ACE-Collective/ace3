"""ttl pools and compressed pools (docs/CAS.md, "Retention modes and churn").

test_ttl (etc/saq.unittest.default.yaml) is a plaintext gzip ttl pool with ttl_days 2, indexed in the
email archive database; email_archive (etc/saq.default.yaml) is the encrypted gzip ttl pool the email
archive uses.
"""

import gzip
import hashlib
import os
from argparse import Namespace

import pytest
from sqlalchemy import func, select

from saq.cas import Hold, IntegrityError, get_cas, index
from saq.cas.health import pool_health
from saq.cli.commands.cas import cli_pools
from saq.crypto import MAGIC
from saq.database.model import CASObject

from tests.saq.cas.conftest import age_object, age_touches, backend_path, records_for

pytestmark = pytest.mark.integration

GRACE = 3600            # etc/saq.unittest.default.yaml cas.default_grace_seconds
TTL_DAYS = 2            # test_ttl's ttl_days
PAST_TTL_SECONDS = TTL_DAYS * 86400 + GRACE + 60
COMPRESSIBLE = b"an archived email compresses well. " * 4000


@pytest.fixture
def ttl_pool():
    return get_cas().pool("test_ttl")


@pytest.fixture
def email_pool():
    return get_cas().pool("email_archive")


def _touches(pool, digest) -> list:
    touch = index.TABLES[pool.database].touch
    with index.transaction(pool.database) as session:
        return list(session.execute(
            select(touch.day).where(touch.pool == pool.name, touch.digest == digest)).scalars())


def _expire(pool, digest):
    """Make an object look as though it was last put before its ttl and grace."""
    age_object(pool, digest, PAST_TTL_SECONDS)
    age_touches(pool, digest, TTL_DAYS + 1)


def test_a_ttl_pool_keeps_its_index_in_its_own_database(ttl_pool):
    digest = ttl_pool.put(COMPRESSIBLE)

    with index.transaction("email_archive") as session:
        assert index.get_object(session, "test_ttl", digest) is not None
        today = session.execute(select(func.curdate())).scalar()

    # nothing in the main database's index
    with index.transaction() as session:
        assert session.execute(select(func.count()).select_from(CASObject).where(CASObject.pool == "test_ttl")).scalar() == 0

    assert _touches(ttl_pool, digest) == [today]


def test_a_second_put_on_the_same_day_adds_no_touch(ttl_pool):
    digest = ttl_pool.put(COMPRESSIBLE)
    ttl_pool.put(COMPRESSIBLE)
    assert len(_touches(ttl_pool, digest)) == 1


def test_gc_collects_a_ttl_object_past_its_ttl(ttl_pool):
    digest = ttl_pool.put(COMPRESSIBLE)
    path = backend_path(ttl_pool, digest)
    _expire(ttl_pool, digest)

    stats = ttl_pool.gc()
    assert (stats.skipped, stats.candidates, stats.deleted) == (False, 1, 1)
    assert not ttl_pool.exists(digest)
    assert not os.path.exists(path)


def test_gc_keeps_a_ttl_object_touched_within_its_ttl(ttl_pool):
    # last_held_at alone says it is old; the touch is what keeps it. No put() produces this state
    # today (every put bumps last_held_at too): it is what the read-side touch will (docs/CAS.md)
    digest = ttl_pool.put(COMPRESSIBLE)
    age_object(ttl_pool, digest, PAST_TTL_SECONDS)
    age_touches(ttl_pool, digest, TTL_DAYS)

    stats = ttl_pool.gc()
    assert (stats.candidates, stats.deleted) == (0, 0)
    assert ttl_pool.exists(digest)


def test_gc_keeps_a_ttl_object_put_within_ttl_and_grace(ttl_pool):
    # the touch has aged out but the last put is inside the ttl plus grace
    digest = ttl_pool.put(COMPRESSIBLE)
    age_object(ttl_pool, digest, TTL_DAYS * 86400)
    age_touches(ttl_pool, digest, TTL_DAYS + 1)

    assert ttl_pool.gc().deleted == 0
    assert ttl_pool.exists(digest)


def test_gc_keeps_an_expired_ttl_object_that_is_held(ttl_pool):
    digest = ttl_pool.put(COMPRESSIBLE, hold=Hold.legal("case-1"))
    _expire(ttl_pool, digest)

    assert ttl_pool.gc().deleted == 0
    assert ttl_pool.exists(digest)


def test_putting_an_expired_object_again_renews_it(ttl_pool):
    digest = ttl_pool.put(COMPRESSIBLE)
    _expire(ttl_pool, digest)

    ttl_pool.put(COMPRESSIBLE)
    assert ttl_pool.gc().deleted == 0
    assert ttl_pool.exists(digest)


def test_gc_flip_rechecks_the_touch(ttl_pool, monkeypatch):
    # a touch between the candidate scan and the flip keeps the object (with last_held_at aged again,
    # as a read-side touch would leave it)
    digest = ttl_pool.put(COMPRESSIBLE)
    _expire(ttl_pool, digest)
    real = index.flip_to_deleting

    def put_then_flip(session, pool, digest_, older_than, touched_within_days):
        ttl_pool.put(COMPRESSIBLE)
        # a put also bumps last_held_at; ageing it again leaves the new touch as the only thing that can stop the flip
        age_object(ttl_pool, digest_, PAST_TTL_SECONDS)
        return real(session, pool, digest_, older_than, touched_within_days)

    monkeypatch.setattr(index, "flip_to_deleting", put_then_flip)
    stats = ttl_pool.gc()
    assert (stats.candidates, stats.skipped_held, stats.deleted) == (1, 1, 0)
    assert ttl_pool.exists(digest)


def test_purge_and_verify_use_the_pools_own_index(ttl_pool):
    digest = ttl_pool.put(COMPRESSIBLE)
    stats = ttl_pool.verify()
    assert (stats.checked, stats.verified) == (1, 1)
    assert ttl_pool.stat(digest).verified_at is not None

    ttl_pool.purge(digest, reason="test", actor="tester")
    assert not ttl_pool.exists(digest)
    purge = index.TABLES["email_archive"].purge
    with index.transaction("email_archive") as session:
        assert session.execute(select(purge.actor).where(purge.digest == digest)).scalar() == "tester"


def test_a_compressed_pool_stores_gzip_and_returns_the_plaintext(ttl_pool, tmp_path):
    digest = ttl_pool.put(COMPRESSIBLE)
    assert digest == hashlib.sha256(COMPRESSIBLE).hexdigest()

    with open(backend_path(ttl_pool, digest), "rb") as fp:
        stored = fp.read()

    assert gzip.decompress(stored) == COMPRESSIBLE
    stat = ttl_pool.stat(digest)
    assert (stat.size, stat.stored_size) == (len(COMPRESSIBLE), len(stored))
    assert stat.stored_size < stat.size

    with ttl_pool.open(digest) as fp:
        assert fp.read() == COMPRESSIBLE

    ttl_pool.materialize(digest, str(tmp_path / "out"))
    assert (tmp_path / "out").read_bytes() == COMPRESSIBLE


def test_a_compressed_encrypted_pool_round_trips(email_pool):
    digest = email_pool.put(COMPRESSIBLE)
    with open(backend_path(email_pool, digest), "rb") as fp:
        stored = fp.read()

    assert stored.startswith(MAGIC)
    assert email_pool.stat(digest).stored_size < len(COMPRESSIBLE)
    with email_pool.open(digest) as fp:
        assert fp.read() == COMPRESSIBLE


@pytest.mark.parametrize("stored, reason", [
    (b"\x1f\x8b not gzip at all", "do not decompress"),
    (gzip.compress(COMPRESSIBLE)[:100], "truncated"),
    (gzip.compress(COMPRESSIBLE) + b"extra", "trailing data"),
])
def test_compressed_bytes_that_do_not_decompress_are_an_integrity_failure(ttl_pool, cas_emitted, caplog, stored, reason):
    digest = ttl_pool.put(COMPRESSIBLE)
    with open(backend_path(ttl_pool, digest), "wb") as fp:
        fp.write(stored)

    with pytest.raises(IntegrityError, match=reason):
        with ttl_pool.open(digest):
            pass

    [record] = records_for(cas_emitted, "error.cas_integrity")
    assert (record["digest"], record["failure"]) == (digest, "digest_mismatch")
    assert any(r.levelname == "ERROR" and getattr(r, "cas_digest", None) == digest for r in caplog.records)


def test_tampered_compressed_ciphertext_is_an_authentication_failure(email_pool, cas_emitted):
    # decompression of the tampered plaintext fails first; the report still says what really happened
    digest = email_pool.put(COMPRESSIBLE)
    path = backend_path(email_pool, digest)
    with open(path, "rb") as fp:
        stored = bytearray(fp.read())

    stored[len(stored) // 2] ^= 0xFF
    with open(path, "wb") as fp:
        fp.write(stored)

    with pytest.raises(IntegrityError):
        with email_pool.open(digest):
            pass

    [record] = records_for(cas_emitted, "error.cas_integrity")
    assert record["failure"] == "authentication"


def test_health_of_a_ttl_pool_skips_the_object_scan(ttl_pool):
    overdue = ttl_pool.put(COMPRESSIBLE)
    ttl_pool.put(b"fresh")
    age_object(ttl_pool, overdue, PAST_TTL_SECONDS + 7200)
    age_touches(ttl_pool, overdue, TTL_DAYS + 1)

    record = {r["pool"]: r for r in pool_health()}["test_ttl"]
    assert record["retention"] == "ttl"
    assert (record["objects_present"], record["size_bytes"], record["stored_bytes"]) == (None, None, None)
    assert (record["objects_deleting"], record["gc_overdue"]) == (0, 1)


def test_health_of_a_ttl_pool_counts_its_stuck_deletions(ttl_pool):
    # what a GC or purge that died between the flip and removing the bytes leaves behind
    stuck = ttl_pool.put(COMPRESSIBLE)
    ttl_pool.put(b"present")
    with index.transaction(ttl_pool.database) as session:
        index.set_deleting_forced(session, ttl_pool.name, stuck)

    record = {r["pool"]: r for r in pool_health()}["test_ttl"]
    assert record["objects_deleting"] == 1


def test_pools_lists_the_ttl_and_the_index_database(ttl_pool, capsys):
    ttl_pool.put(COMPRESSIBLE)
    assert cli_pools(Namespace()) == 0
    line = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("test_ttl "))
    assert "ttl" in line and f"{TTL_DAYS}d" in line and "email_archive" in line
    assert f" 1 {len(COMPRESSIBLE)} " in " ".join(line.split()) + " "
