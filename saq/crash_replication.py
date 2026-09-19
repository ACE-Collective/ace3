"""Replicating analysis module crash reports to shared object storage.

A crash report is written to the local disk of whichever node's worker crashed
(``saq/crash_report.py``). The database index is cluster-wide but the bytes are not, so without
this module an analyst who asks node B for a report that lives on node A gets a 409 telling them
to go find the right host.

When ``crash_reporting.replicate`` is on, every report is also copied into a shared bucket keyed
by crash id, and any node can serve any report. The report then survives the owning node being
**down, rebuilt, or decommissioned**.

This lives outside ``saq/crash_report.py`` on purpose. That module is imported by the engine's
crash paths and by the API, and it deliberately keeps heavy dependencies out of its import graph
(see its lazy ``saq.database`` import). ``saq.storage`` pulls in boto3, which is not even a core
dependency, so the same discipline applies: it is imported lazily, from inside functions, behind
the config check.

**Nothing here may raise or block the crash path.** Two rules follow:

*Never raise* -- every public function swallows and logs, the same contract ``record_module_crash``
holds itself to.

*Never block* -- uploads happen on a daemon thread that is **never joined**. S3 requests are
bounded (``saq/storage/s3.py`` sets connect/read timeouts and caps retries), but bounded is not
instant: a report is several objects, each a multipart transfer of several requests, and the
caller here is an engine worker holding a work item lock. Seconds of object store round trip still
have no business on the crash path. The local report is already durable before any of this starts,
so replication is pure best-effort and ``ace crash sync`` is the catch-up.

The upload order matters: **``metadata.json`` is uploaded last**, mirroring the local convention
where it is written last. A ``<crash_id>/metadata.json`` key therefore means the remote copy is
complete, and objects present without it mean the copy was interrupted -- the same sentinel, read
the same way, so a partially replicated report is still served and still reports itself incomplete.
"""

import logging
import os
import threading
from typing import Optional

from saq.crash_report import METADATA_FILE, is_valid_crash_id

# How many replication threads may be in flight per process. Acquired non-blocking: if the budget
# is gone we skip and let `ace crash sync` catch up, rather than queueing work onto the crash path.
# Crashes arrive in bursts (a module that fails on every file in a tree), so an unbounded thread
# per crash is not acceptable.
_MAX_CONCURRENT_UPLOADS = 2
_upload_slots = threading.Semaphore(_MAX_CONCURRENT_UPLOADS)


def replication_enabled() -> bool:
    """True if crash reports should be replicated to shared storage.

    The single place this config is read. Deliberately an explicit opt-in rather than something
    inferred from ``storage.target``: a cluster running the local backend with ``base_dir`` on a
    shared filesystem is a perfectly good deployment, and inferring would silently disable
    replication in exactly that case with no signal to the operator.
    """
    try:
        from saq.configuration.config import get_config

        config = get_config().crash_reporting
        return bool(config.enabled and config.replicate)
    except Exception as e:
        logging.debug("unable to read crash replication config: %s", e)
        return False


def _bucket() -> str:
    from saq.configuration.config import get_config

    return get_config().crash_reporting.storage_bucket


def _storage():
    # imported here rather than at module level: saq.storage pulls in boto3, which is not a core
    # dependency, and this module is imported from the engine's crash path
    from saq.storage import get_storage_system

    return get_storage_system()


def object_key(crash_id: str, relative_path: str) -> str:
    """The object key for one file of one report. Derivable from the crash id, which is why this
    feature needs no database column and no migration."""
    return f"{crash_id}/{relative_path.replace(os.sep, '/')}"


def _iter_report_files(crash_dir: str) -> list[str]:
    """Every file in the report, as paths relative to the report directory."""
    results = []
    for dirpath, _, file_names in os.walk(crash_dir):
        for file_name in file_names:
            full_path = os.path.join(dirpath, file_name)
            results.append(os.path.relpath(full_path, start=crash_dir))

    return results


#
# write path
#

def replicate_report(crash_dir: str, crash_id: str) -> bool:
    """Upload one crash report to shared storage. Returns True if the report is now complete there.

    Synchronous, and the seam tests drive. ``metadata.json`` goes last so the remote copy has the
    same completeness sentinel as the local one; if anything fails partway, what landed is still
    useful and still identifiably incomplete.
    """
    try:
        if not is_valid_crash_id(crash_id):
            logging.warning("refusing to replicate invalid crash id %s", crash_id)
            return False

        if not os.path.isdir(crash_dir):
            logging.warning("crash report directory %s no longer exists", crash_dir)
            return False

        storage = _storage()
        bucket = _bucket()

        relative_paths = _iter_report_files(crash_dir)
        # everything except metadata.json first, then metadata.json as the completeness marker
        payload = sorted(p for p in relative_paths if p != METADATA_FILE)
        has_metadata = METADATA_FILE in relative_paths

        for relative_path in payload:
            storage.upload_file(
                os.path.join(crash_dir, relative_path), bucket, object_key(crash_id, relative_path)
            )

        if has_metadata:
            storage.upload_file(
                os.path.join(crash_dir, METADATA_FILE), bucket, object_key(crash_id, METADATA_FILE)
            )

        logging.info(
            "replicated crash report to shared storage",
            extra={"crash_id": crash_id, "files": len(relative_paths), "bucket": bucket},
        )
        return has_metadata

    except Exception as e:
        # a failed replication costs cross-node availability, never the report itself
        logging.warning("unable to replicate crash report %s: %s", crash_id, e)
        return False


def replicate_async(crash_dir: str, crash_id: str) -> bool:
    """Start replicating in the background. Returns True if a thread was started.

    Never joined, by design -- see the module docstring. The caller is on the crash path and must
    not wait on an object store.
    """
    try:
        if not _upload_slots.acquire(blocking=False):
            logging.debug(
                "crash replication busy, deferring %s to `ace crash sync`", crash_id
            )
            return False

        def _run():
            try:
                replicate_report(crash_dir, crash_id)
            except Exception as e:
                # replicate_report does not raise, but an exception escaping a thread target would
                # reach threading.excepthook and print to stderr from inside a worker
                logging.warning("crash replication thread failed for %s: %s", crash_id, e)
            finally:
                _upload_slots.release()

        threading.Thread(target=_run, name=f"crash-replication-{crash_id[:8]}", daemon=True).start()
        return True

    except Exception as e:
        logging.warning("unable to start crash replication for %s: %s", crash_id, e)
        return False


#
# read path
#

def remote_report_exists(crash_id: str) -> bool:
    """True if a *complete* copy of this report is in shared storage."""
    try:
        if not is_valid_crash_id(crash_id):
            return False

        return bool(_storage().object_exists(_bucket(), object_key(crash_id, METADATA_FILE)))
    except Exception as e:
        logging.warning("unable to check shared storage for crash report %s: %s", crash_id, e)
        return False


def list_remote_files(crash_id: str) -> list[str]:
    """The relative paths of this report's files in shared storage."""
    try:
        if not is_valid_crash_id(crash_id):
            return []

        prefix = f"{crash_id}/"
        keys = _storage().list_objects(_bucket(), prefix=prefix, recursive=True) or []
        results = []
        for key in keys:
            key = getattr(key, "object_name", key)
            if isinstance(key, str) and key.startswith(prefix):
                results.append(key[len(prefix):])

        return sorted(results)
    except Exception as e:
        logging.warning("unable to list shared storage for crash report %s: %s", crash_id, e)
        return []


def fetch_report(crash_id: str, dest_parent: str) -> Optional[str]:
    """Download a whole report from shared storage into ``dest_parent/<crash_id>/``.

    Returns the report directory, or None. The layout matches a local report directory exactly, so
    every downstream reader (metadata parsing, the encrypted zip) works on it unchanged.
    """
    try:
        relative_paths = list_remote_files(crash_id)
        if not relative_paths:
            return None

        storage = _storage()
        bucket = _bucket()
        crash_dir = os.path.join(dest_parent, crash_id)

        for relative_path in relative_paths:
            local_path = os.path.join(crash_dir, relative_path)
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            storage.download_file(bucket, object_key(crash_id, relative_path), local_path)

        return crash_dir

    except Exception as e:
        logging.warning("unable to fetch crash report %s from shared storage: %s", crash_id, e)
        return None


def fetch_metadata(crash_id: str, dest_parent: str) -> Optional[dict]:
    """Download and parse just this report's metadata.json, for the detail endpoint."""
    try:
        import json

        if not is_valid_crash_id(crash_id):
            return None

        local_path = os.path.join(dest_parent, f"{crash_id}-{METADATA_FILE}")
        _storage().download_file(_bucket(), object_key(crash_id, METADATA_FILE), local_path)
        try:
            with open(local_path) as fp:
                return json.load(fp)
        finally:
            try:
                os.remove(local_path)
            except OSError:
                pass

    except FileNotFoundError:
        return None
    except Exception as e:
        logging.warning("unable to fetch crash metadata %s from shared storage: %s", crash_id, e)
        return None


def remote_file_sizes(crash_id: str) -> dict[str, int]:
    """Sizes for this report's remote files, so the API's file inventory stays populated."""
    sizes = {}
    try:
        storage = _storage()
        bucket = _bucket()
        for relative_path in list_remote_files(crash_id):
            info = storage.get_object_info(bucket, object_key(crash_id, relative_path))
            if info and info.get("size") is not None:
                sizes[relative_path] = int(info["size"])
    except Exception as e:
        logging.warning("unable to size crash report %s in shared storage: %s", crash_id, e)

    return sizes


#
# maintenance
#

def list_replicated_ids() -> set[str]:
    """The crash ids that have a *complete* copy in the bucket, from one listing.

    This is what makes the sweeper stateless: no marker file to write into the report directory
    (which would leak into the API's file inventory, into the analyst's archive, and -- worst --
    would refresh the directory mtime that `ace crash prune` ages reports by).

    Ids are derived from ``<id>/metadata.json`` keys rather than from a delimiter listing of
    prefixes. A prefix listing looks cheaper, but the local backend maps objects to real
    directories and leaves an empty one behind after a delete, so a deleted report would keep
    showing up as replicated forever. Keying off the completeness marker answers the question the
    sweeper actually asks -- "is there a finished copy up there" -- and is correct on every backend.
    """
    try:
        keys = _storage().list_objects(_bucket(), prefix="", recursive=True) or []
        results = set()
        suffix = f"/{METADATA_FILE}"
        for key in keys:
            key = getattr(key, "object_name", key)
            if not isinstance(key, str) or not key.endswith(suffix):
                continue
            candidate = key[: -len(suffix)]
            if is_valid_crash_id(candidate):
                results.add(candidate)

        return results
    except Exception as e:
        logging.warning("unable to list replicated crash reports: %s", e)
        return set()


def delete_report(crash_id: str) -> bool:
    """Remove every object for this report. Returns True if the report is gone from storage."""
    try:
        if not is_valid_crash_id(crash_id):
            return False

        storage = _storage()
        bucket = _bucket()
        relative_paths = list_remote_files(crash_id)
        if not relative_paths:
            return True

        # metadata.json first: it is the completeness marker, so dropping it first means an
        # interrupted delete leaves a report that reads as incomplete rather than as intact
        ordered = [METADATA_FILE] if METADATA_FILE in relative_paths else []
        ordered += [p for p in relative_paths if p != METADATA_FILE]

        for relative_path in ordered:
            storage.delete_object(bucket, object_key(crash_id, relative_path))

        return True

    except Exception as e:
        logging.warning("unable to delete replicated crash report %s: %s", crash_id, e)
        return False
