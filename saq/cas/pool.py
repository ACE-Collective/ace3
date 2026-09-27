"""A CAS pool: the API every consumer uses (docs/CAS.md, "API" and "Lifecycle").

    pool = get_cas().pool("svs_samples")
    digest = pool.put(src, hold=Hold("svs_capture", capture_id))
    with pool.open(digest) as stream: ...
    pool.materialize(digest, dest_path)

Every operation runs one (purge: two) short private transaction against the index. put() and
hold() lock the object row FOR UPDATE, which is what serializes them against the GC flip. open()
and materialize() never hand out unverified bytes: a plaintext object is re-hashed and an
encrypted one has its tag checked before anything is released.
"""

import hashlib
import logging
import os
import shutil
import tempfile
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import BinaryIO, Iterator, Optional, Union

from saq.cas import index
from saq.cas.backend import CASBackend, LocalBackend, digest_from_key, is_digest, object_key
from saq.cas.cache import ReadCache
from saq.cas.errors import (
    BackendError,
    BackendKeyNotFound,
    CASError,
    DigestMismatch,
    IntegrityError,
    InvalidDigest,
    KeyMismatch,
    LegalHoldActive,
    ObjectDeleting,
    ObjectNotFound,
)
from saq.cas.hold import Hold
from saq.configuration.schema import CASConfig, CASPoolConfig
from saq.crypto import FORMAT_V1, CryptoError, KeyMismatchError, decrypt_stream, encrypt_stream
from saq.environment import get_global_runtime_settings, get_temp_dir
from saq.monitor import Monitor, emit_monitor
from saq.monitor_definitions import (
    MONITOR_CAS_GC,
    MONITOR_CAS_INTEGRITY,
    MONITOR_CAS_ORPHANS,
    MONITOR_CAS_VERIFY,
)

_CHUNK = 1024 * 1024
_ORPHAN_LOOKUP_BATCH = 500
_DELETING_POLL_SECONDS = 0.5
# a verify run's record carries at most this many failed digests; the full list is on stdout
_MAX_REPORTED_FAILURES = 20

# the cas_failure / failure value on an integrity report (docs/CAS.md, "Observability")
FAILURE_DIGEST_MISMATCH = "digest_mismatch"     # plaintext bytes hash to something else
FAILURE_AUTHENTICATION = "authentication"       # an encrypted object failed its GCM tag or header check
FAILURE_KEY_MISMATCH = "key_mismatch"           # encrypted under a different system key than the loaded one
FAILURE_MISSING_BYTES = "missing_bytes"         # the index row is present but the backend has no bytes

_FAILURE_MESSAGES = {
    FAILURE_DIGEST_MISMATCH: "cas object failed verification",
    FAILURE_AUTHENTICATION: "cas object failed verification",
    FAILURE_KEY_MISMATCH: "cas object was encrypted with a different key than the one loaded",
    FAILURE_MISSING_BYTES: "cas object is in the index but its bytes are missing",
}


@dataclass(frozen=True)
class ObjectStat:
    pool: str
    digest: str
    size: int
    stored_size: int
    key_id: Optional[str]
    state: str
    created_at: datetime
    last_held_at: datetime
    verified_at: Optional[datetime]
    hold_count: int


@dataclass
class GCStats:
    pool: str
    dry_run: bool
    skipped: bool = False          # the pool's retention has no GC (permanent)
    resumed: int = 0               # objects a previous run left in deleting and this one finished
    candidates: int = 0
    deleted: int = 0
    skipped_held: int = 0          # a hold arrived between the candidate scan and the flip
    bytes_reclaimed: int = 0
    expired_holds_pruned: int = 0
    errors: int = 0


@dataclass
class VerifyStats:
    pool: str
    dry_run: bool
    checked: int = 0
    verified: int = 0
    mismatched: int = 0            # corrupt: the bytes fail their hash or authentication
    key_mismatch: int = 0          # encrypted under a key other than the loaded one (a key problem, not corruption)
    missing: int = 0
    failures: list[str] = field(default_factory=list)


@dataclass
class OrphanStats:
    pool: str
    dry_run: bool
    scanned: int = 0
    orphaned: int = 0              # bytes with no index row, whatever their age
    deleted: int = 0
    bytes_reclaimed: int = 0
    skipped_within_grace: int = 0
    unparseable: int = 0
    temp_files_removed: int = 0


@dataclass
class _Spooled:
    path: str
    digest: str
    size: int
    owned: bool     # True when path is a temp file put() has to remove


class _HashingWriter:
    """A write() target that hashes what passes through and optionally forwards it."""

    def __init__(self, target: Optional[BinaryIO]):
        self.hasher = hashlib.sha256()
        self.target = target

    def write(self, data: bytes) -> int:
        self.hasher.update(data)
        if self.target is not None:
            self.target.write(data)

        return len(data)

    @property
    def digest(self) -> str:
        return self.hasher.hexdigest()


class CASPool:
    def __init__(self, name: str, config: CASPoolConfig, cas_config: CASConfig, backend: CASBackend, cache: ReadCache):
        self.name = name
        self.config = config
        self.cas_config = cas_config
        self.backend = backend
        self.cache = cache
        self.grace_seconds = config.grace_seconds if config.grace_seconds is not None else cas_config.default_grace_seconds

    def __repr__(self) -> str:
        return f"CASPool({self.name!r})"

    @property
    def encrypted(self) -> bool:
        return self.config.encryption == "system"

    @property
    def retention(self) -> str:
        return self.config.retention

    def key(self, digest: str) -> str:
        return object_key(self.name, digest)

    @staticmethod
    def _check_digest(digest: str) -> None:
        if not is_digest(digest):
            raise InvalidDigest(f"{digest!r} is not a lowercase hex sha256")

    # a plaintext object in a backend that can hand out hardlinks is used in place (verified by
    # re-hashing); everything else goes through the read cache as a verified plaintext copy
    @property
    def _direct(self) -> bool:
        return not self.encrypted and self.backend.node_local and hasattr(self.backend, "link")

    #
    # write side
    #

    def put(self, src: Union[str, bytes, BinaryIO], *, hold: Optional[Hold] = None,
            digest: Optional[str] = None, created_by: Optional[str] = None) -> str:
        """Store src (a path, bytes or a readable binary stream) and return its digest. Atomic and
        idempotent: storing content that exists is a no-op except for the hold. If digest is given
        and the content hashes to something else, nothing is stored and DigestMismatch is raised.
        The hold is taken in the same transaction that makes the object exist, so there is no
        window in which GC could see an unreferenced object."""
        if digest is not None:
            self._check_digest(digest)

        spooled = self._spool(src)
        try:
            if digest is not None and spooled.digest != digest:
                raise DigestMismatch(digest, spooled.digest)

            stored_path, stored_size, key_id = spooled.path, spooled.size, None
            encrypted_path = None
            if self.encrypted:
                fd, encrypted_path = tempfile.mkstemp(dir=get_temp_dir(), prefix="cas-enc-")
                with open(spooled.path, "rb") as fp_in, os.fdopen(fd, "wb") as fp_out:
                    result = encrypt_stream(fp_in, fp_out, size=spooled.size, format_version=FORMAT_V1)

                stored_path, stored_size, key_id = encrypted_path, result.stored_size, result.key_id

            try:
                self._commit_put(spooled.digest, spooled.size, stored_size, key_id, stored_path, hold, created_by)
            finally:
                if encrypted_path is not None:
                    _unlink_quietly(encrypted_path)
        finally:
            if spooled.owned:
                _unlink_quietly(spooled.path)

        return spooled.digest

    def _spool(self, src: Union[str, bytes, BinaryIO]) -> _Spooled:
        if isinstance(src, str):
            with open(src, "rb") as fp:
                digest = hashlib.file_digest(fp, "sha256").hexdigest()

            return _Spooled(path=src, digest=digest, size=os.path.getsize(src), owned=False)

        hasher = hashlib.sha256()
        size = 0
        fd, temp_path = tempfile.mkstemp(dir=get_temp_dir(), prefix="cas-put-")
        try:
            with os.fdopen(fd, "wb") as fp:
                if isinstance(src, (bytes, bytearray, memoryview)):
                    data = bytes(src)
                    hasher.update(data)
                    fp.write(data)
                    size = len(data)
                else:
                    while True:
                        chunk = src.read(_CHUNK)
                        if not chunk:
                            break

                        hasher.update(chunk)
                        fp.write(chunk)
                        size += len(chunk)
        except BaseException:
            _unlink_quietly(temp_path)
            raise

        return _Spooled(path=temp_path, digest=hasher.hexdigest(), size=size, owned=True)

    def _commit_put(self, digest: str, size: int, stored_size: int, key_id: Optional[str],
                    stored_path: str, hold: Optional[Hold], created_by: Optional[str]) -> None:
        key = self.key(digest)
        deadline = time.monotonic() + self.cas_config.put_deleting_wait_seconds
        while True:
            with index.transaction() as session:
                # INSERT IGNORE then lock: two first-time puts of one digest both get here, the
                # second blocks on the first's row until it commits, then finds the row present
                index.insert_object_if_absent(session, self.name, digest, size, stored_size, key_id)
                row = index.lock_object(session, self.name, digest)
                if row is None:
                    logging.error("cas object vanished under its row lock", extra={"cas_pool": self.name, "cas_digest": digest})
                    raise CASError(f"cas object {self.name}/{digest} vanished under its lock")

                if row.state != index.STATE_DELETING:
                    # under the row lock, so GC cannot flip this object and remove the bytes
                    # between this check and the commit that references them
                    if not self.backend.exists(key):
                        with open(stored_path, "rb") as fp:
                            self.backend.write(key, fp)

                    if hold is not None:
                        index.upsert_hold(session, self.name, digest, hold, created_by)

                    index.touch_last_held(session, self.name, digest)
                    return

            # GC or purge is removing it: wait for the row to go, then the loop re-inserts and
            # re-uploads. nothing was changed in the transaction above, so committing it is a no-op
            if time.monotonic() >= deadline:
                logging.warning("cas put gave up waiting for an object that is being deleted", extra={
                    "cas_pool": self.name, "cas_digest": digest,
                    "waited_seconds": self.cas_config.put_deleting_wait_seconds})
                raise ObjectDeleting(self.name, digest)

            time.sleep(_DELETING_POLL_SECONDS)

    def hold(self, digest: str, hold: Hold, *, created_by: Optional[str] = None) -> None:
        """Take (or renew) a hold. Idempotent; a new expires_at replaces the old one."""
        self._check_digest(digest)
        with index.transaction() as session:
            row = index.lock_object(session, self.name, digest)
            if row is None:
                raise ObjectNotFound(self.name, digest)

            if row.state == index.STATE_DELETING:
                raise ObjectDeleting(self.name, digest)

            index.upsert_hold(session, self.name, digest, hold, created_by)
            index.touch_last_held(session, self.name, digest)

    def release(self, digest: str, hold: Hold) -> bool:
        """Release a hold. Returns False when there was no such hold (not an error). The object's
        grace period counts from the last release."""
        self._check_digest(digest)
        with index.transaction() as session:
            row = index.lock_object(session, self.name, digest)
            if row is None:
                raise ObjectNotFound(self.name, digest)

            removed = index.delete_hold(session, self.name, digest, hold)
            if removed:
                index.touch_last_held(session, self.name, digest)

            return removed > 0

    #
    # read side
    #

    def exists(self, digest: str) -> bool:
        self._check_digest(digest)
        with index.transaction() as session:
            return index.get_object(session, self.name, digest) is not None

    def stat(self, digest: str) -> ObjectStat:
        self._check_digest(digest)
        with index.transaction() as session:
            row = index.get_object(session, self.name, digest)
            if row is None:
                raise ObjectNotFound(self.name, digest)

            return ObjectStat(
                pool=self.name, digest=digest, size=row.size, stored_size=row.stored_size,
                key_id=row.key_id, state=row.state, created_at=row.created_at,
                last_held_at=row.last_held_at, verified_at=row.verified_at,
                hold_count=index.count_holds(session, self.name, digest))

    def holds(self, digest: str) -> list[Hold]:
        self._check_digest(digest)
        with index.transaction() as session:
            return [Hold(row.holder_kind, row.holder_id, row.expires_at)
                    for row in index.list_holds(session, self.name, digest)]

    def _require_row(self, digest: str) -> None:
        # a deleting row is still opened: the reader may find the bytes gone mid-way and get
        # ObjectNotFound, which is the accepted race (docs/CAS.md)
        self._check_digest(digest)
        with index.transaction() as session:
            if index.get_object(session, self.name, digest) is None:
                raise ObjectNotFound(self.name, digest)

    def _verify_and_fill(self, digest: str, target: Optional[BinaryIO], operation: str) -> None:
        """Stream the object's plaintext into target (or nowhere), verifying it. For an encrypted
        pool the GCM tag and key id are checked and the plaintext re-hashed; for a plaintext pool
        the bytes are re-hashed. Raises IntegrityError (KeyMismatch for the wrong key) before
        returning if anything is off, so target must be private until this returns. Every failure
        is reported here, once, whoever the caller is; operation names the caller in the report."""
        key = self.key(digest)
        writer = _HashingWriter(target)
        try:
            with self.backend.open(key) as source:
                if self.encrypted:
                    try:
                        decrypt_stream(source, writer)
                    except KeyMismatchError as e:
                        self._report_integrity_failure(digest, operation, FAILURE_KEY_MISMATCH, e,
                                                       stored_key_id=e.header_key_id, loaded_key_id=e.current_key_id)
                        raise KeyMismatch(f"cas object {self.name}/{digest}: {e}", e.header_key_id, e.current_key_id) from e
                    except CryptoError as e:
                        self._report_integrity_failure(digest, operation, FAILURE_AUTHENTICATION, e)
                        raise IntegrityError(f"cas object {self.name}/{digest}: {e}") from e
                else:
                    shutil.copyfileobj(source, writer, _CHUNK)
        except BackendKeyNotFound:
            raise self._missing(digest, operation) from None

        if writer.digest != digest:
            error = IntegrityError(f"cas object {self.name}/{digest}: stored bytes hash to {writer.digest}")
            self._report_integrity_failure(digest, operation, FAILURE_DIGEST_MISMATCH, error)
            raise error

    def _missing(self, digest: str, operation: str) -> ObjectNotFound:
        """The backend has no bytes for digest: returns the ObjectNotFound to raise. If the index
        still says the object is present, the index and the backend disagree, and that is
        reported. A row that is deleting or gone is the accepted race with GC or purge (the bytes
        go before the row), and so is bytes that exist again by the time we look (a put re-uploaded
        them)."""
        try:
            with index.transaction() as session:
                row = index.get_object(session, self.name, digest)
                state = row.state if row is not None else None

            divergent = state == index.STATE_PRESENT and not self.backend.exists(self.key(digest))
        except Exception as e:
            logging.warning("cas unable to check the index row of an object with missing bytes", extra={
                "cas_pool": self.name, "cas_digest": digest, "cas_operation": operation, "error": str(e)})
            divergent = False

        if divergent:
            self._report_integrity_failure(digest, operation, FAILURE_MISSING_BYTES,
                                           "the index row is present but the backend has no bytes")
        else:
            logging.debug("cas object %s/%s went away during %s", self.name, digest, operation)

        return ObjectNotFound(self.name, digest)

    def _report_integrity_failure(self, digest: str, operation: str, failure: str, error: Union[Exception, str],
                                  stored_key_id: Optional[str] = None, loaded_key_id: Optional[str] = None) -> None:
        """ERROR log plus an error.cas_integrity monitor record. Nothing here raises: it runs on
        the way to raising the real error."""
        fields = {"cas_pool": self.name, "cas_digest": digest, "cas_operation": operation,
                  "cas_failure": failure, "error": str(error)}
        if stored_key_id is not None:
            fields["cas_stored_key_id"] = stored_key_id

        if loaded_key_id is not None:
            fields["cas_loaded_key_id"] = loaded_key_id

        logging.error(_FAILURE_MESSAGES[failure], extra=fields)
        _emit(MONITOR_CAS_INTEGRITY, {
            "node": _node(), "pool": self.name, "digest": digest, "operation": operation, "failure": failure,
            "error": str(error), "stored_key_id": stored_key_id, "loaded_key_id": loaded_key_id})

    def _emit_run(self, monitor: Monitor, stats, started: float) -> None:
        """The cas.gc / cas.verify / cas.orphans record for one run over this pool."""
        data = asdict(stats)
        failures = data.pop("failures", None)
        if failures is not None:
            data["failures"] = failures[:_MAX_REPORTED_FAILURES]
            data["failures_truncated"] = len(failures) > _MAX_REPORTED_FAILURES

        data["node"] = _node()
        data["duration_seconds"] = round(time.monotonic() - started, 3)
        _emit(monitor, data)

    @contextmanager
    def _plaintext_path(self, digest: str, operation: str) -> Iterator[str]:
        """A path holding the verified plaintext, from the read cache or a temp file."""
        if self.cache.enabled:
            yield self.cache.get_or_fill(self.name, digest, lambda fp: self._verify_and_fill(digest, fp, operation))
            return

        fd, temp_path = tempfile.mkstemp(dir=get_temp_dir(), prefix="cas-read-")
        try:
            with os.fdopen(fd, "wb") as fp:
                self._verify_and_fill(digest, fp, operation)

            yield temp_path
        finally:
            _unlink_quietly(temp_path)

    @contextmanager
    def open(self, digest: str) -> Iterator[BinaryIO]:
        """A readable stream of the object's plaintext. Integrity is verified before the first
        byte is available."""
        self._require_row(digest)
        if self._direct:
            self._verify_and_fill(digest, None, "open")
            try:
                with self.backend.open(self.key(digest)) as fp:
                    yield fp
            except BackendKeyNotFound:
                raise self._missing(digest, "open") from None

            return

        with self._plaintext_path(digest, "open") as path:
            with open(path, "rb") as fp:
                yield fp

    def materialize(self, digest: str, dest_path: str) -> None:
        """Put the object's plaintext at dest_path: a hardlink when the backend is local and the
        pool is plaintext, otherwise a hardlink out of the read cache, otherwise a copy. dest_path
        must not exist."""
        self._require_row(digest)
        if self._direct:
            self._verify_and_fill(digest, None, "materialize")
            key = self.key(digest)
            if self.backend.link(key, dest_path):
                return

            try:
                with self.backend.open(key) as source, open(dest_path, "wb") as target:
                    shutil.copyfileobj(source, target, _CHUNK)
            except BackendKeyNotFound:
                raise self._missing(digest, "materialize") from None

            return

        with self._plaintext_path(digest, "materialize") as path:
            try:
                os.link(path, dest_path)
            except FileExistsError:
                raise
            except OSError:
                shutil.copyfile(path, dest_path)

    #
    # deletion
    #

    def _delete_bytes(self, digest: str) -> None:
        self.backend.delete(self.key(digest))
        self.cache.remove(self.name, digest)

    def purge(self, digest: str, *, reason: str, actor: Optional[str]) -> None:
        """Forced deletion across holds, audited in cas_purges. Refuses while a legal hold exists."""
        self._check_digest(digest)
        if not reason:
            raise ValueError("a purge needs a reason")

        with index.transaction() as session:
            row = index.lock_object(session, self.name, digest)
            if row is None:
                raise ObjectNotFound(self.name, digest)

            if index.legal_hold_exists(session, self.name, digest):
                raise LegalHoldActive(self.name, digest)

            index.set_deleting_forced(session, self.name, digest)

        # from here put() and hold() see deleting. if this fails the row stays deleting and the
        # next GC run finishes the job (its resume step)
        self._delete_bytes(digest)

        with index.transaction() as session:
            index.delete_object_row(session, self.name, digest)
            index.insert_purge(session, self.name, digest, reason, actor)

        logging.info("cas purge", extra={"cas_pool": self.name, "cas_digest": digest, "actor": actor, "reason": reason})

    def _finish_delete(self, digest: str, stats: GCStats) -> None:
        """Delete the bytes, then the row, of an object already flipped to deleting."""
        with index.transaction() as session:
            row = index.get_object(session, self.name, digest)
            stored_size = row.stored_size if row is not None else 0

        try:
            self._delete_bytes(digest)
        except (BackendError, OSError) as e:
            # the row stays deleting; the next run's resume step retries
            logging.error("cas gc unable to delete an object's bytes", extra={
                "cas_pool": self.name, "cas_digest": digest, "error": str(e)})
            stats.errors += 1
            return

        with index.transaction() as session:
            index.delete_object_row(session, self.name, digest)

        stats.deleted += 1
        stats.bytes_reclaimed += stored_size

    def _pause(self) -> None:
        if self.cas_config.gc_batch_pause_seconds > 0:
            time.sleep(self.cas_config.gc_batch_pause_seconds)

    def gc(self, *, dry_run: bool = False) -> GCStats:
        """Garbage-collect a held pool: finish deletions a previous run left behind, then remove
        every object that has had no live hold for longer than the grace period, in batches of
        primary keys with a pause between them, then prune expired hold rows the same way.
        A permanent pool is never collected."""
        stats = GCStats(pool=self.name, dry_run=dry_run)
        if self.retention != "held":
            stats.skipped = True
            return stats

        started = time.monotonic()

        batch = self.cas_config.gc_batch_size

        # 0. resume: objects flipped by a run (or a purge) that died before removing them
        while True:
            with index.transaction() as session:
                digests = index.deleting_objects(session, self.name, batch)

            if not digests:
                break

            for digest in digests:
                stats.resumed += 1
                if not dry_run:
                    self._finish_delete(digest, stats)

            if dry_run or len(digests) < batch:
                break

            self._pause()

        # 1. candidates, in primary-key order, one conditional flip per object
        after = ""
        while True:
            with index.transaction() as session:
                digests = index.gc_candidates(session, self.name, self.grace_seconds, after, batch)

            if not digests:
                break

            for digest in digests:
                stats.candidates += 1
                if dry_run:
                    continue

                with index.transaction() as session:
                    flipped = index.flip_to_deleting(session, self.name, digest, self.grace_seconds)

                if not flipped:
                    stats.skipped_held += 1
                    continue

                self._finish_delete(digest, stats)

            after = digests[-1]
            if len(digests) < batch:
                break

            self._pause()

        # 2. expired hold rows
        if not dry_run:
            while True:
                with index.transaction() as session:
                    pruned = index.delete_expired_holds_batch(session, self.name, batch)

                stats.expired_holds_pruned += pruned
                if pruned < batch:
                    break

                self._pause()

        logging.info("cas gc", extra={
            "cas_pool": self.name, "dry_run": dry_run, "resumed": stats.resumed,
            "candidates": stats.candidates, "deleted": stats.deleted, "skipped_held": stats.skipped_held,
            "bytes_reclaimed": stats.bytes_reclaimed, "expired_holds_pruned": stats.expired_holds_pruned,
            "errors": stats.errors})
        self._emit_run(MONITOR_CAS_GC, stats, started)
        return stats

    #
    # maintenance
    #

    def verify(self, *, sample_size: Optional[int] = None, dry_run: bool = False) -> VerifyStats:
        """Re-hash a sample of objects and record verified_at on the ones that are intact. A
        corrupt or missing object is reported loudly and never deleted."""
        stats = VerifyStats(pool=self.name, dry_run=dry_run)
        started = time.monotonic()
        count = sample_size if sample_size is not None else self.cas_config.verify_sample_size
        with index.transaction() as session:
            digests = [row.digest for row in index.sample_objects(session, self.name, count)]

        # each failure is logged (and emitted as error.cas_integrity) by _verify_and_fill
        for digest in digests:
            stats.checked += 1
            try:
                self._verify_and_fill(digest, None, "verify")
            except ObjectNotFound:
                stats.missing += 1
                stats.failures.append(digest)
                continue
            except KeyMismatch:
                stats.key_mismatch += 1
                stats.failures.append(digest)
                continue
            except IntegrityError:
                stats.mismatched += 1
                stats.failures.append(digest)
                continue

            stats.verified += 1
            if not dry_run:
                with index.transaction() as session:
                    index.set_verified(session, self.name, digest)

        logging.info("cas verify", extra={
            "cas_pool": self.name, "dry_run": dry_run, "checked": stats.checked, "verified": stats.verified,
            "mismatched": stats.mismatched, "key_mismatch": stats.key_mismatch, "missing": stats.missing})
        self._emit_run(MONITOR_CAS_VERIFY, stats, started)
        return stats

    def orphans(self, *, grace_seconds: Optional[int] = None, dry_run: bool = False) -> OrphanStats:
        """List the backend and remove bytes that have no index row and are older than the grace
        period (so an in-flight put is never mistaken for an orphan). The only operation that
        lists the backend."""
        stats = OrphanStats(pool=self.name, dry_run=dry_run)
        started = time.monotonic()
        grace = grace_seconds if grace_seconds is not None else self.cas_config.orphan_grace_seconds
        cutoff = time.time() - grace
        prefix = f"{self.name}/"
        pending = []

        def flush():
            with index.transaction() as session:
                present = index.digests_present(session, self.name, [digest_from_key(entry.key) for entry in pending])

            for entry in pending:
                if digest_from_key(entry.key) in present:
                    continue

                stats.orphaned += 1
                if entry.mtime >= cutoff:
                    stats.skipped_within_grace += 1
                    continue

                if not dry_run:
                    self.backend.delete(entry.key)

                stats.deleted += 1
                stats.bytes_reclaimed += entry.size

            pending.clear()

        for entry in self.backend.iter_entries(prefix):
            stats.scanned += 1
            if not entry.key.startswith(prefix) or digest_from_key(entry.key) is None:
                logging.warning("cas orphans: %s has a key the CAS would not write: %s", self.name, entry.key)
                stats.unparseable += 1
                continue

            pending.append(entry)
            if len(pending) >= _ORPHAN_LOOKUP_BATCH:
                flush()

        flush()

        if isinstance(self.backend, LocalBackend) and not dry_run:
            stats.temp_files_removed = self.backend.sweep_temp_files(cutoff)

        logging.info("cas orphans", extra={
            "cas_pool": self.name, "dry_run": dry_run, "scanned": stats.scanned, "orphaned": stats.orphaned,
            "deleted": stats.deleted, "bytes_reclaimed": stats.bytes_reclaimed,
            "skipped_within_grace": stats.skipped_within_grace, "unparseable": stats.unparseable,
            "temp_files_removed": stats.temp_files_removed})
        self._emit_run(MONITOR_CAS_ORPHANS, stats, started)
        return stats


def _node() -> Optional[str]:
    return get_global_runtime_settings().saq_node


def _emit(monitor: Monitor, data: dict) -> None:
    # a monitor record is telemetry: failing to send one must never fail the CAS operation (or the
    # error being raised) that produced it
    try:
        emit_monitor(monitor, data)
    except Exception as e:
        logging.debug("unable to emit %s: %s", monitor.path, e)


def _unlink_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
