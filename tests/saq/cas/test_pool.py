import hashlib
import io
import logging
import os
import threading
import time
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select, text

from saq.cas import (
    DigestMismatch,
    Hold,
    IntegrityError,
    InvalidDigest,
    KeyMismatch,
    LegalHoldActive,
    ObjectDeleting,
    ObjectNotFound,
    get_cas,
    index,
)
from saq.crypto import FORMAT_V1, MAGIC, V1_HEADER_SIZE, encrypt_stream, get_key_id
from saq.database.model import CASPurge
from saq.database.pool import get_db
from saq.environment import get_data_dir, get_temp_dir

from saq.cas import metrics
from saq.cas.pool import VerifyStats
from saq.monitor_definitions import MONITOR_CAS_VERIFY

from tests.saq.cas.conftest import age_object, backend_path, records_for

pytestmark = pytest.mark.integration

GRACE = 3600   # etc/saq.unittest.default.yaml cas.default_grace_seconds


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def dest_dir(tmp_path_factory):
    """A destination directory on the same filesystem as the pools and the read cache (tmp_path
    is on another device here, where a hardlink is impossible)."""
    path = os.path.join(get_data_dir(), "cas_test_dest")
    os.makedirs(path, exist_ok=True)
    return path


def _no_temp_files(prefix: str) -> bool:
    return not any(name.startswith(prefix) for name in os.listdir(get_temp_dir()))


#
# put
#

def test_put_plaintext(plain_pool, payload):
    digest = plain_pool.put(payload)
    assert digest == _sha(payload)

    stat = plain_pool.stat(digest)
    assert stat.size == len(payload)
    assert stat.stored_size == len(payload)
    assert stat.key_id is None
    assert stat.state == "present"
    assert stat.hold_count == 0
    assert stat.verified_at is None
    assert plain_pool.exists(digest)

    with open(backend_path(plain_pool, digest), "rb") as fp:
        assert fp.read() == payload

    assert _no_temp_files("cas-put-")


def test_put_encrypted(enc_pool, payload):
    digest = enc_pool.put(payload)
    assert digest == _sha(payload)

    stat = enc_pool.stat(digest)
    assert stat.size == len(payload)
    assert stat.stored_size == V1_HEADER_SIZE + len(payload) + 16
    assert stat.key_id == get_key_id()

    with open(backend_path(enc_pool, digest), "rb") as fp:
        stored = fp.read()

    assert stored[:7] == MAGIC and stored[7] == FORMAT_V1
    assert payload not in stored
    assert len(stored) == stat.stored_size
    assert _no_temp_files("cas-put-") and _no_temp_files("cas-enc-")


def test_put_is_idempotent(plain_pool, payload):
    digest = plain_pool.put(payload)
    before = os.stat(backend_path(plain_pool, digest))
    assert plain_pool.put(payload) == digest
    after = os.stat(backend_path(plain_pool, digest))
    assert before.st_ino == after.st_ino
    assert plain_pool.stat(digest).hold_count == 0

    with index.transaction() as session:
        assert session.execute(text("SELECT COUNT(*) FROM cas_objects WHERE pool = 'test_plain'")).scalar() == 1


def test_put_sources_agree(plain_pool, payload, tmp_path):
    path = tmp_path / "src"
    path.write_bytes(payload)
    assert plain_pool.put(str(path)) == plain_pool.put(io.BytesIO(payload)) == plain_pool.put(payload) == _sha(payload)
    assert path.exists()   # a path source is not consumed


def test_put_with_hold(plain_pool, payload):
    digest = plain_pool.put(payload, hold=Hold("svs_capture", "42"), created_by="tester")
    assert plain_pool.stat(digest).hold_count == 1
    assert plain_pool.holds(digest) == [Hold("svs_capture", "42")]

    # a second put with another hold adds it
    plain_pool.put(payload, hold=Hold("svs_capture", "43"))
    assert plain_pool.stat(digest).hold_count == 2


def test_put_expected_digest(plain_pool, payload):
    digest = plain_pool.put(payload, digest=_sha(payload))
    assert plain_pool.exists(digest)

    other = _sha(b"something else")
    with pytest.raises(DigestMismatch) as e:
        plain_pool.put(payload + b"x", digest=other)

    assert e.value.expected == other and e.value.actual == _sha(payload + b"x")
    assert not plain_pool.exists(e.value.actual)
    assert not os.path.exists(backend_path(plain_pool, e.value.actual))
    assert _no_temp_files("cas-put-")

    with pytest.raises(InvalidDigest):
        plain_pool.put(payload, digest="not-a-digest")


def test_put_waits_for_a_deleting_object_then_reuploads(plain_pool, payload):
    digest = plain_pool.put(payload)
    with index.transaction() as session:
        index.set_deleting_forced(session, plain_pool.name, digest)

    # GC is half way through: bytes gone, row still there
    os.unlink(backend_path(plain_pool, digest))

    result = {}

    def putter():
        try:
            result["digest"] = plain_pool.put(payload, hold=Hold("k", "1"))
        except Exception as e:
            result["error"] = e

    thread = threading.Thread(target=putter)
    thread.start()
    time.sleep(1.0)
    assert thread.is_alive()   # still waiting on the deleting row

    with index.transaction() as session:
        index.delete_object_row(session, plain_pool.name, digest)

    thread.join(timeout=10)
    assert not thread.is_alive()
    assert result == {"digest": digest}

    stat = plain_pool.stat(digest)
    assert stat.state == "present" and stat.hold_count == 1
    with open(backend_path(plain_pool, digest), "rb") as fp:
        assert fp.read() == payload


def test_concurrent_puts_of_one_object_do_not_deadlock(enc_pool):
    # many captures of one sample at once. a duplicate-key INSERT IGNORE takes a shared lock on the
    # existing row, and two puts that both then asked for FOR UPDATE deadlocked on the upgrade
    payload = os.urandom(4096)
    digest = enc_pool.put(payload)
    threads, puts = 8, 25
    barrier = threading.Barrier(threads)
    errors = []

    def putter(n):
        barrier.wait()
        for i in range(puts):
            try:
                enc_pool.put(payload, hold=Hold("svs_capture", f"{n}-{i}"))
            except Exception as e:
                errors.append(e)

    workers = [threading.Thread(target=putter, args=(n,)) for n in range(threads)]
    for worker in workers:
        worker.start()

    for worker in workers:
        worker.join(timeout=120)

    assert errors == []
    assert enc_pool.stat(digest).hold_count == threads * puts


def test_operations_are_timed_by_phase(enc_pool, payload, dest_dir):
    metrics.reset()
    digest = enc_pool.put(payload)
    enc_pool.put(payload)
    enc_pool.materialize(digest, os.path.join(dest_dir, f"timed-{digest}"))
    phases = {(r["operation"], r["phase"]): r["count"] for r in metrics.snapshot(enc_pool.name)}
    assert phases[("put", "total")] == 2
    assert phases[("put", "encrypt")] == 2
    assert phases[("put", "write")] == 1
    assert phases[("put", "deduplicated")] == 1
    assert phases[("materialize", "total")] == 1
    assert phases[("materialize", "verify")] == 1


def test_put_gives_up_on_a_deleting_object(plain_pool, payload, monkeypatch, caplog):
    digest = plain_pool.put(payload)
    with index.transaction() as session:
        index.set_deleting_forced(session, plain_pool.name, digest)

    monkeypatch.setattr(plain_pool.cas_config, "put_deleting_wait_seconds", 0.2)
    with caplog.at_level(logging.WARNING), pytest.raises(ObjectDeleting):
        plain_pool.put(payload)

    assert any(r.levelno == logging.WARNING and getattr(r, "cas_digest", None) == digest for r in caplog.records)


#
# holds
#

def test_hold_is_idempotent_and_renews(plain_pool, payload):
    digest = plain_pool.put(payload)
    plain_pool.hold(digest, Hold("k", "1"))
    plain_pool.hold(digest, Hold("k", "1"))
    assert plain_pool.stat(digest).hold_count == 1
    assert plain_pool.holds(digest)[0].expires_at is None

    later = (datetime.now() + timedelta(days=1)).replace(microsecond=0)
    plain_pool.hold(digest, Hold("k", "1", expires_at=later))
    assert plain_pool.stat(digest).hold_count == 1
    assert plain_pool.holds(digest)[0].expires_at == later


def test_hold_on_unknown_or_deleting_object(plain_pool, payload):
    with pytest.raises(ObjectNotFound):
        plain_pool.hold(_sha(b"nothing"), Hold("k", "1"))

    digest = plain_pool.put(payload)
    with index.transaction() as session:
        index.set_deleting_forced(session, plain_pool.name, digest)

    with pytest.raises(ObjectDeleting):
        plain_pool.hold(digest, Hold("k", "1"))


def test_release(plain_pool, payload):
    digest = plain_pool.put(payload, hold=Hold("k", "1"))
    age_object(plain_pool, digest, 10 * GRACE)
    old = plain_pool.stat(digest).last_held_at

    assert plain_pool.release(digest, Hold("k", "1")) is True
    assert plain_pool.release(digest, Hold("k", "1")) is False
    assert plain_pool.stat(digest).hold_count == 0
    # the grace period counts from the release
    assert plain_pool.stat(digest).last_held_at > old

    with pytest.raises(ObjectNotFound):
        plain_pool.release(_sha(b"nothing"), Hold("k", "1"))


#
# gc
#

def test_gc_respects_grace(plain_pool, payload):
    digest = plain_pool.put(payload, hold=Hold("k", "1"))
    plain_pool.release(digest, Hold("k", "1"))

    stats = plain_pool.gc()
    assert (stats.candidates, stats.deleted) == (0, 0)
    assert plain_pool.exists(digest)

    age_object(plain_pool, digest, GRACE + 60)
    stats = plain_pool.gc()
    assert (stats.candidates, stats.deleted, stats.skipped_held) == (1, 1, 0)
    assert stats.bytes_reclaimed == len(payload)
    assert not plain_pool.exists(digest)
    assert not os.path.exists(backend_path(plain_pool, digest))


def test_gc_dry_run_changes_nothing(plain_pool, payload):
    digest = plain_pool.put(payload)
    age_object(plain_pool, digest, GRACE + 60)
    stats = plain_pool.gc(dry_run=True)
    assert stats.dry_run and stats.candidates == 1 and stats.deleted == 0
    assert plain_pool.exists(digest) and plain_pool.stat(digest).state == "present"


def test_gc_skips_held_objects(plain_pool, payload):
    digest = plain_pool.put(payload, hold=Hold("k", "1"))
    age_object(plain_pool, digest, GRACE + 60)
    stats = plain_pool.gc()
    assert (stats.candidates, stats.deleted) == (0, 0)
    assert plain_pool.exists(digest)


def test_gc_treats_expired_holds_as_none(plain_pool, payload):
    expired = datetime.now() - timedelta(days=1)
    digest = plain_pool.put(payload, hold=Hold("k", "1", expires_at=expired))
    age_object(plain_pool, digest, GRACE + 60)
    stats = plain_pool.gc()
    assert stats.deleted == 1
    assert not plain_pool.exists(digest)


def test_gc_prunes_expired_hold_rows(plain_pool, payload):
    expired = datetime.now() - timedelta(days=1)
    digest = plain_pool.put(payload, hold=Hold("k", "live"))
    plain_pool.hold(digest, Hold("k", "expired", expires_at=expired))
    assert plain_pool.stat(digest).hold_count == 2

    stats = plain_pool.gc()
    assert stats.deleted == 0
    assert stats.expired_holds_pruned == 1
    assert plain_pool.holds(digest) == [Hold("k", "live")]


def test_gc_batches_in_key_order(plain_pool, monkeypatch):
    # the unittest config sets gc_batch_size to 10; 25 objects means three batches
    digests = [plain_pool.put(os.urandom(32)) for _ in range(25)]
    for digest in digests:
        age_object(plain_pool, digest, GRACE + 60)

    calls = []
    real = index.gc_candidates

    def spy(session, pool, grace, after, limit):
        result = real(session, pool, grace, after, limit)
        calls.append((after, len(result)))
        return result

    monkeypatch.setattr(index, "gc_candidates", spy)
    stats = plain_pool.gc()
    assert stats.deleted == 25
    assert [count for _, count in calls] == [10, 10, 5]
    assert calls[0][0] == "" and calls[1][0] == sorted(digests)[9] and calls[2][0] == sorted(digests)[19]


def test_gc_flip_is_conditional_on_holds(plain_pool, payload, monkeypatch):
    digest = plain_pool.put(payload)
    age_object(plain_pool, digest, GRACE + 60)

    real = index.flip_to_deleting

    def hold_then_flip(session, pool, digest_, grace):
        # somebody takes a hold after the candidate scan and before the flip
        plain_pool.hold(digest_, Hold("k", "late"))
        return real(session, pool, digest_, grace)

    monkeypatch.setattr(index, "flip_to_deleting", hold_then_flip)
    stats = plain_pool.gc()
    assert (stats.candidates, stats.skipped_held, stats.deleted) == (1, 1, 0)
    assert plain_pool.stat(digest).state == "present"
    assert os.path.exists(backend_path(plain_pool, digest))


def test_gc_resumes_an_interrupted_delete(plain_pool, payload):
    digest = plain_pool.put(payload)
    with index.transaction() as session:
        index.set_deleting_forced(session, plain_pool.name, digest)

    stats = plain_pool.gc()
    assert stats.resumed == 1 and stats.deleted == 1
    assert not plain_pool.exists(digest)
    assert not os.path.exists(backend_path(plain_pool, digest))


def test_permanent_pool_is_never_collected(perm_pool, payload):
    digest = perm_pool.put(payload)
    age_object(perm_pool, digest, 100 * GRACE)
    stats = perm_pool.gc()
    assert stats.skipped and stats.deleted == 0
    assert perm_pool.exists(digest)


#
# purge
#

def _purge_rows(pool, digest):
    return get_db().execute(select(CASPurge).where(CASPurge.pool == pool.name, CASPurge.digest == digest)).scalars().all()


def test_purge_refuses_a_legal_hold(plain_pool, payload):
    digest = plain_pool.put(payload, hold=Hold("k", "1"))
    plain_pool.hold(digest, Hold.legal("case-7"), created_by="counsel")

    with pytest.raises(LegalHoldActive):
        plain_pool.purge(digest, reason="mistake", actor="admin")

    assert plain_pool.stat(digest).state == "present"
    assert plain_pool.stat(digest).hold_count == 2
    assert _purge_rows(plain_pool, digest) == []

    plain_pool.release(digest, Hold.legal("case-7"))
    plain_pool.purge(digest, reason="mistake", actor="admin")
    assert not plain_pool.exists(digest)


def test_purge_removes_everything_and_audits(enc_pool, payload):
    digest = enc_pool.put(payload, hold=Hold("k", "1"))
    enc_pool.hold(digest, Hold("k", "2"))
    with enc_pool.open(digest) as fp:
        fp.read()   # populate the read cache
    assert os.path.exists(get_cas().cache.path(enc_pool.name, digest))

    enc_pool.purge(digest, reason="customer request", actor="admin")

    assert not enc_pool.exists(digest)
    assert not os.path.exists(backend_path(enc_pool, digest))
    assert not os.path.exists(get_cas().cache.path(enc_pool.name, digest))
    with index.transaction() as session:
        assert index.count_holds(session, enc_pool.name, digest) == 0

    rows = _purge_rows(enc_pool, digest)
    assert len(rows) == 1
    assert (rows[0].reason, rows[0].actor) == ("customer request", "admin")

    with pytest.raises(ObjectNotFound):
        enc_pool.purge(digest, reason="again", actor="admin")

    with pytest.raises(ValueError):
        enc_pool.purge(digest, reason="", actor="admin")


#
# open / materialize
#

def test_open_plaintext_and_encrypted(plain_pool, enc_pool, payload):
    for pool in (plain_pool, enc_pool):
        digest = pool.put(payload)
        with pool.open(digest) as fp:
            assert fp.read() == payload

    with pytest.raises(ObjectNotFound):
        with plain_pool.open(_sha(b"nothing")):
            pass


def test_open_detects_a_corrupt_plaintext_object(plain_pool, payload):
    digest = plain_pool.put(payload)
    path = backend_path(plain_pool, digest)
    data = bytearray(open(path, "rb").read())
    data[len(data) // 2] ^= 0x01
    open(path, "wb").write(bytes(data))

    with pytest.raises(IntegrityError):
        with plain_pool.open(digest):
            pass

    with pytest.raises(IntegrityError):
        plain_pool.materialize(digest, path + ".out")

    assert not os.path.exists(path + ".out")


@pytest.mark.parametrize("where", ["body", "header", "tag"])
def test_open_detects_a_corrupt_encrypted_object(enc_pool, payload, where):
    digest = enc_pool.put(payload)
    path = backend_path(enc_pool, digest)
    data = bytearray(open(path, "rb").read())
    offset = {"body": V1_HEADER_SIZE + 10, "header": 20, "tag": len(data) - 1}[where]
    data[offset] ^= 0x01
    open(path, "wb").write(bytes(data))

    with pytest.raises(IntegrityError):
        with enc_pool.open(digest):
            pass

    cache_root = get_cas().cache.root
    assert not os.path.exists(get_cas().cache.path(enc_pool.name, digest))
    assert not any(name.startswith(".fill-") for _, _, names in os.walk(cache_root) for name in names)


def test_open_detects_the_wrong_key(enc_pool, payload):
    digest = enc_pool.put(payload)
    path = backend_path(enc_pool, digest)
    with open(path, "wb") as fp:
        encrypt_stream(io.BytesIO(payload), fp, size=len(payload), password="not the system key")

    with pytest.raises(IntegrityError, match="encrypted with key"):
        with enc_pool.open(digest):
            pass


def test_materialize_plaintext_local_is_a_hardlink(plain_pool, payload, dest_dir):
    digest = plain_pool.put(payload)
    dest = os.path.join(dest_dir, "sample")
    plain_pool.materialize(digest, dest)
    assert open(dest, "rb").read() == payload
    assert os.stat(dest).st_ino == os.stat(backend_path(plain_pool, digest)).st_ino

    with pytest.raises(FileExistsError):
        plain_pool.materialize(digest, dest)

    # the object survives its hardlink's deletion and its deletion survives the hardlink
    os.unlink(dest)
    plain_pool.materialize(digest, dest)
    plain_pool.purge(digest, reason="test", actor=None)
    assert open(dest, "rb").read() == payload


def test_materialize_copies_across_filesystems(plain_pool, payload, tmp_path):
    digest = plain_pool.put(payload)
    dest = tmp_path / "sample"
    plain_pool.materialize(digest, str(dest))
    assert dest.read_bytes() == payload


def test_materialize_encrypted_goes_through_the_read_cache(enc_pool, payload, dest_dir):
    digest = enc_pool.put(payload)
    dest = os.path.join(dest_dir, "sample")
    enc_pool.materialize(digest, dest)
    assert open(dest, "rb").read() == payload

    cached = get_cas().cache.path(enc_pool.name, digest)
    assert os.path.exists(cached)
    assert os.stat(dest).st_ino == os.stat(cached).st_ino

    # a second materialize is served from the cache without touching the backend
    os.unlink(backend_path(enc_pool, digest))
    again = os.path.join(dest_dir, "again")
    enc_pool.materialize(digest, again)
    assert open(again, "rb").read() == payload


def test_materialize_copies_when_the_cache_entry_is_evicted_after_the_open(enc_pool, payload, dest_dir, monkeypatch):
    # the cached name is gone by the time materialize() links it: the open file is still intact
    digest = enc_pool.put(payload)
    cache = get_cas().cache
    open_or_fill = cache.open_or_fill

    def evicting_open_or_fill(pool, digest, fill):
        fp = open_or_fill(pool, digest, fill)
        os.unlink(fp.name)
        return fp

    monkeypatch.setattr(cache, "open_or_fill", evicting_open_or_fill)
    dest = os.path.join(dest_dir, f"evicted-{digest}")
    enc_pool.materialize(digest, dest)
    with open(dest, "rb") as fp:
        assert fp.read() == payload


def test_materialize_into_a_missing_directory_raises(enc_pool, payload, dest_dir):
    digest = enc_pool.put(payload)
    with pytest.raises(FileNotFoundError):
        enc_pool.materialize(digest, os.path.join(dest_dir, "missing", "out"))


def test_read_cache_disabled_uses_a_temp_file(enc_pool, payload, monkeypatch):
    monkeypatch.setattr(get_cas().cache, "max_bytes", 0)
    digest = enc_pool.put(payload)
    with enc_pool.open(digest) as fp:
        assert fp.read() == payload

    assert not os.path.exists(get_cas().cache.path(enc_pool.name, digest))
    assert _no_temp_files("cas-read-")


def test_stat_and_exists_on_unknown_objects(plain_pool):
    assert plain_pool.exists(_sha(b"nothing")) is False
    with pytest.raises(ObjectNotFound):
        plain_pool.stat(_sha(b"nothing"))

    with pytest.raises(InvalidDigest):
        plain_pool.stat("nope")


#
# verify / orphans
#

def test_verify(plain_pool, enc_pool, payload):
    for pool in (plain_pool, enc_pool):
        digest = pool.put(payload)
        stats = pool.verify()
        assert (stats.checked, stats.verified, stats.mismatched, stats.missing) == (1, 1, 0, 0)
        assert pool.stat(digest).verified_at is not None

    digest = plain_pool.put(b"another")
    path = backend_path(plain_pool, digest)
    open(path, "wb").write(b"anotheR")
    stats = plain_pool.verify(sample_size=10)
    assert stats.checked == 2 and stats.mismatched == 1 and stats.failures == [digest]
    assert plain_pool.exists(digest)      # reported, never deleted

    os.unlink(path)
    stats = plain_pool.verify(sample_size=10)
    assert stats.missing == 1 and plain_pool.exists(digest)

    stats = plain_pool.verify(sample_size=1, dry_run=True)
    assert stats.checked == 1


def test_orphans(plain_pool, payload):
    digest = plain_pool.put(payload)
    shard = os.path.dirname(backend_path(plain_pool, digest))

    old_digest = _sha(b"old orphan")
    old_path = os.path.join(plain_pool.backend.root, plain_pool.key(old_digest))
    os.makedirs(os.path.dirname(old_path), exist_ok=True)
    open(old_path, "wb").write(b"old orphan")
    os.utime(old_path, (1, 1))

    new_digest = _sha(b"new orphan")
    new_path = os.path.join(plain_pool.backend.root, plain_pool.key(new_digest))
    os.makedirs(os.path.dirname(new_path), exist_ok=True)
    open(new_path, "wb").write(b"new orphan")

    stray = os.path.join(shard, "not-a-digest")
    open(stray, "wb").write(b"?")
    os.utime(stray, (1, 1))

    stats = plain_pool.orphans(dry_run=True)
    assert (stats.scanned, stats.orphaned, stats.deleted, stats.skipped_within_grace, stats.unparseable) == (4, 2, 1, 1, 1)
    assert os.path.exists(old_path)

    stats = plain_pool.orphans()
    assert stats.deleted == 1 and stats.bytes_reclaimed == len(b"old orphan")
    assert not os.path.exists(old_path)
    assert os.path.exists(new_path) and os.path.exists(stray)
    assert os.path.exists(backend_path(plain_pool, digest))

    stats = plain_pool.orphans(grace_seconds=0)
    assert stats.deleted == 1
    assert not os.path.exists(new_path)


#
# observability (docs/CAS.md, "Observability")
#

def _corrupt(path: str, offset: int) -> None:
    data = bytearray(open(path, "rb").read())
    data[offset] ^= 0x01
    open(path, "wb").write(bytes(data))


def _integrity_errors(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno == logging.ERROR and hasattr(r, "cas_failure")]


def test_corrupt_plaintext_is_reported(plain_pool, payload, cas_emitted, caplog):
    digest = plain_pool.put(payload)
    _corrupt(backend_path(plain_pool, digest), len(payload) // 2)

    with caplog.at_level(logging.ERROR), pytest.raises(IntegrityError):
        with plain_pool.open(digest):
            pass

    [record] = records_for(cas_emitted, "error.cas_integrity")
    assert (record["pool"], record["digest"], record["operation"], record["failure"]) == \
        ("test_plain", digest, "open", "digest_mismatch")
    [log] = _integrity_errors(caplog)
    assert (log.cas_pool, log.cas_digest, log.cas_operation, log.cas_failure) == ("test_plain", digest, "open", "digest_mismatch")


def test_corrupt_encrypted_is_reported(enc_pool, payload, dest_dir, cas_emitted, caplog):
    digest = enc_pool.put(payload)
    _corrupt(backend_path(enc_pool, digest), V1_HEADER_SIZE + 10)

    with caplog.at_level(logging.ERROR), pytest.raises(IntegrityError) as raised:
        enc_pool.materialize(digest, os.path.join(dest_dir, "corrupt.out"))

    assert not isinstance(raised.value, KeyMismatch)
    [record] = records_for(cas_emitted, "error.cas_integrity")
    assert (record["operation"], record["failure"]) == ("materialize", "authentication")
    assert [log.cas_failure for log in _integrity_errors(caplog)] == ["authentication"]


def test_wrong_key_is_reported_as_a_key_mismatch(enc_pool, payload, cas_emitted, caplog):
    digest = enc_pool.put(payload)
    with open(backend_path(enc_pool, digest), "wb") as fp:
        encrypt_stream(io.BytesIO(payload), fp, size=len(payload), password="not the system key", format_version=FORMAT_V1)

    with caplog.at_level(logging.ERROR), pytest.raises(KeyMismatch) as raised:
        with enc_pool.open(digest):
            pass

    assert raised.value.loaded_key_id == get_key_id()
    assert raised.value.stored_key_id != get_key_id()
    [record] = records_for(cas_emitted, "error.cas_integrity")
    assert record["failure"] == "key_mismatch"
    assert (record["stored_key_id"], record["loaded_key_id"]) == (raised.value.stored_key_id, get_key_id())
    [log] = _integrity_errors(caplog)
    assert log.cas_failure == "key_mismatch" and log.cas_loaded_key_id == get_key_id()


def test_missing_bytes_under_a_present_row_is_reported(plain_pool, payload, cas_emitted, caplog):
    digest = plain_pool.put(payload)
    os.unlink(backend_path(plain_pool, digest))

    with caplog.at_level(logging.ERROR), pytest.raises(ObjectNotFound):
        with plain_pool.open(digest):
            pass

    [record] = records_for(cas_emitted, "error.cas_integrity")
    assert record["failure"] == "missing_bytes"
    assert [log.cas_failure for log in _integrity_errors(caplog)] == ["missing_bytes"]


def test_missing_bytes_under_a_deleting_row_is_the_accepted_race(plain_pool, payload, cas_emitted, caplog):
    digest = plain_pool.put(payload)
    with index.transaction() as session:
        index.set_deleting_forced(session, plain_pool.name, digest)

    os.unlink(backend_path(plain_pool, digest))
    with caplog.at_level(logging.ERROR), pytest.raises(ObjectNotFound):
        with plain_pool.open(digest):
            pass

    assert records_for(cas_emitted, "error.cas_integrity") == []
    assert _integrity_errors(caplog) == []


def test_verify_does_not_fail_on_an_object_gc_removed_after_the_sample(plain_pool, payload, monkeypatch, cas_emitted):
    # the hourly GC and the weekly verify start in the same minute
    digest = plain_pool.put(payload)
    sample_objects = index.sample_objects

    def sample_then_gc(session, pool, count):
        rows = sample_objects(session, pool, count)
        with index.transaction() as other:
            index.set_deleting_forced(other, pool, digest)

        os.unlink(backend_path(plain_pool, digest))
        return rows

    monkeypatch.setattr(index, "sample_objects", sample_then_gc)
    stats = plain_pool.verify()
    assert (stats.checked, stats.verified, stats.missing, stats.removed) == (1, 0, 0, 1)
    assert stats.failures == []
    assert records_for(cas_emitted, "error.cas_integrity") == []


def test_verify_counts_a_key_mismatch_apart_from_corruption(enc_pool, payload, cas_emitted):
    digest = enc_pool.put(payload)
    with open(backend_path(enc_pool, digest), "wb") as fp:
        encrypt_stream(io.BytesIO(payload), fp, size=len(payload), password="not the system key", format_version=FORMAT_V1)

    stats = enc_pool.verify()
    assert (stats.checked, stats.verified, stats.mismatched, stats.key_mismatch, stats.missing) == (1, 0, 0, 1, 0)
    assert stats.failures == [digest]

    [integrity] = records_for(cas_emitted, "error.cas_integrity")
    assert (integrity["operation"], integrity["failure"]) == ("verify", "key_mismatch")
    [run] = records_for(cas_emitted, "cas.verify")
    assert (run["pool"], run["key_mismatch"], run["failures"], run["failures_truncated"]) == \
        ("test_encrypted", 1, [digest], False)


def test_maintenance_runs_emit_one_record_each(plain_pool, perm_pool, payload, cas_emitted):
    digest = plain_pool.put(payload)
    age_object(plain_pool, digest, GRACE + 60)

    plain_pool.gc(dry_run=True)
    plain_pool.gc()
    perm_pool.gc()       # permanent: nothing runs, nothing is emitted
    plain_pool.verify()
    plain_pool.orphans()

    dry_run, real = records_for(cas_emitted, "cas.gc")
    assert (dry_run["pool"], dry_run["dry_run"], dry_run["candidates"], dry_run["deleted"]) == ("test_plain", True, 1, 0)
    assert (real["dry_run"], real["deleted"], real["bytes_reclaimed"], real["errors"]) == (False, 1, len(payload), 0)
    assert "node" in real and real["duration_seconds"] >= 0

    [verify] = records_for(cas_emitted, "cas.verify")
    assert (verify["pool"], verify["checked"], verify["failures"]) == ("test_plain", 0, [])
    [orphans] = records_for(cas_emitted, "cas.orphans")
    assert (orphans["pool"], orphans["scanned"], orphans["deleted"]) == ("test_plain", 0, 0)


def test_gc_delete_failure_is_counted_and_reported(plain_pool, payload, cas_emitted, caplog, monkeypatch):
    digest = plain_pool.put(payload)
    age_object(plain_pool, digest, GRACE + 60)

    def fail(key):
        raise OSError("disk on fire")

    monkeypatch.setattr(plain_pool.backend, "delete", fail)
    with caplog.at_level(logging.ERROR):
        stats = plain_pool.gc()

    assert (stats.deleted, stats.errors) == (0, 1)
    assert plain_pool.stat(digest).state == "deleting"      # the next run's resume step retries
    assert any(getattr(r, "cas_digest", None) == digest and r.levelno == logging.ERROR for r in caplog.records)
    [run] = records_for(cas_emitted, "cas.gc")
    assert run["errors"] == 1


def test_verify_record_caps_its_failure_list(plain_pool, cas_emitted):
    stats = VerifyStats(pool=plain_pool.name, dry_run=False, failures=[f"{i:064x}" for i in range(25)])
    plain_pool._emit_run(MONITOR_CAS_VERIFY, stats, time.monotonic())
    [run] = records_for(cas_emitted, "cas.verify")
    assert len(run["failures"]) == 20 and run["failures_truncated"] is True
