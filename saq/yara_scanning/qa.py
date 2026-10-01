"""Matches of rules in QA mode, recorded by the yara scanner service (docs/YARA_SCANNER.md,
docs/YARA_QA.md).

Recording a QA match takes database transactions and CAS puts that hash and encrypt the whole file.
A scanning worker must never wait on that, so the work is split across two processes that share
nothing but a spool directory:

- QASpooler runs in each worker. When a scan_file request carries a `qa` object and a rule in QA
  mode matched, it hardlinks the scanned file into the spool before the worker answers, and writes
  the job after the answer is sent. The hardlink keeps the bytes even if the engine deletes the
  file before they are recorded. It never touches the database.
- QARecorder runs in the qa recorder process, which the manager owns. It drains the spool into
  saq.yara_qa.store, oldest job first, at a lower CPU priority than the workers.

A spool job is two files, both named <time_ns>-<pid>-<sequence>:

    <job>.file    the scanned file: a hardlink, or a copy when it cannot be linked
    <job>.json    {"v", "qa", "matches", "attempts"}: the request's qa object, and the QA matches
                  encoded the way the protocol encodes them. It is written last, by rename, so it
                  is the job's commit marker

The recorder claims a job by renaming <job>.json to <job>.claimed. A job still claimed when a
recorder starts was interrupted by a crash or a kill. It is dropped, so a job that crashes the
recorder cannot crash it again and is never counted twice.
"""

import errno
import json
import logging
import os
import select
import shutil
import time
from dataclasses import dataclass
from typing import Callable, Optional

from sqlalchemy.exc import DisconnectionError, InterfaceError, OperationalError

from saq.error.reporting import log_loop_exception, report_exception
from saq.signatures.yara_meta import meta_enabled, meta_is_qa
from saq.yara_qa.store import QATarget, record_qa_match_or_raise
from saq.yara_scanning import protocol

SPOOL_VERSION = 1

JOB_SUFFIX = ".json"
CLAIMED_SUFFIX = ".claimed"
FILE_SUFFIX = ".file"
TMP_SUFFIX = ".tmp"

# how often the recorder looks at the spool when it is empty
POLL_INTERVAL = 1.0
# how long the recorder waits before trying again while the database is unreachable
DATABASE_RETRY_SECONDS = 30
# a job that still cannot be recorded after this many tries is dropped, so a database error that
# only looks transient cannot hold up the jobs behind it forever
MAX_ATTEMPTS = 20

# a .file without a job, or a .tmp, older than this was left by a process that died writing it
ORPHAN_AGE_SECONDS = 600
ORPHAN_SWEEP_INTERVAL = 300
# how often the recorder logs how many jobs are waiting, while there are any
DEPTH_LOG_INTERVAL = 60

# how long a worker trusts its count of the jobs in the spool
SPOOL_COUNT_SECONDS = 5
# a worker logs at most one spooling warning per this many seconds
WARNING_INTERVAL = 60

# the recorder hashes and encrypts whole files: it yields the CPU to the scanning workers
RECORDER_NICENESS = 10

# why os.link() can fail on a file that can still be copied
_CANNOT_LINK = (errno.EXDEV, errno.EPERM, errno.EMLINK)

# errors that mean the database is unreachable for now, rather than that the match cannot be stored
TRANSIENT_ERRORS = (OperationalError, InterfaceError, DisconnectionError)


def select_qa_matches(matches: list[dict]) -> list[dict]:
    """The matches the recorder keeps: rules in QA mode that are enabled and have a uuid to file
    the match under. The scanner module ignores disabled rules the same way, and the store skips
    rules without a uuid."""
    result = []
    for match in matches:
        meta = match.get("meta") or {}
        if meta_enabled(meta) and meta_is_qa(meta) and str(meta.get("uuid") or "").strip():
            result.append(match)

    return result


def _job_path(spool_dir: str, name: str, suffix: str) -> str:
    return os.path.join(spool_dir, name + suffix)


def _unlink(path: str):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _write_json(path: str, data: dict):
    temp_path = path + TMP_SUFFIX
    with open(temp_path, "w") as fp:
        json.dump(data, fp)

    os.replace(temp_path, path)


def count_jobs(spool_dir: str) -> int:
    """The jobs waiting in the spool, including the one being recorded."""
    with os.scandir(spool_dir) as entries:
        return sum(1 for entry in entries if entry.name.endswith((JOB_SUFFIX, CLAIMED_SUFFIX)))


#
# worker side
#

@dataclass
class PendingJob:
    name: str
    qa: dict
    matches: list[dict]
    # the scanned file, held open when it could not be linked
    fd: Optional[int] = None


class QASpooler:
    """Runs in a scanning worker. Nothing here raises: a failure is logged and the matches are not
    recorded, and the scan is answered either way."""

    def __init__(self, spool_dir: str, max_jobs: int):
        self.spool_dir = spool_dir
        self.max_jobs = max_jobs
        self.sequence = 0
        self.counted_jobs = 0
        self.counted_at: Optional[float] = None
        self.warned_at: Optional[float] = None

    def begin(self, request: dict, response: dict) -> Optional[PendingJob]:
        """Called before the response is sent. If a rule in QA mode matched, pins the scanned file
        so the engine cannot delete it from under the recorder, and returns the job to commit."""
        if not request.get("qa") or response.get("status") != protocol.STATUS_OK:
            return None

        try:
            matches = select_qa_matches(response.get("matches") or [])
            if not matches:
                return None

            if self._full():
                self._warn("the yara qa spool %s holds %d jobs: the qa matches of %s are dropped",
                           self.spool_dir, self.counted_jobs, request["path"])
                return None

            self.sequence += 1
            job = PendingJob(f"{time.time_ns()}-{os.getpid()}-{self.sequence}", request["qa"], matches)
            try:
                os.link(request["path"], _job_path(self.spool_dir, job.name, FILE_SUFFIX))
            except OSError as e:
                if e.errno not in _CANNOT_LINK:
                    raise

                # another filesystem, or linking is not allowed: hold the file open and copy it
                # once the client has its answer
                job.fd = os.open(request["path"], os.O_RDONLY)

            return job

        except Exception as e:
            self._warn("unable to spool the yara qa matches of %s: %s", request.get("path"), e)
            return None

    def commit(self, job: PendingJob):
        """Called after the response is sent: writes the job."""
        file_path = _job_path(self.spool_dir, job.name, FILE_SUFFIX)
        try:
            if job.fd is not None:
                with os.fdopen(job.fd, "rb") as src, open(file_path, "wb") as dst:
                    job.fd = None
                    shutil.copyfileobj(src, dst, 1024 * 1024)

            _write_json(_job_path(self.spool_dir, job.name, JOB_SUFFIX),
                        {"v": SPOOL_VERSION, "qa": job.qa, "matches": job.matches, "attempts": 0})
            self.counted_jobs += 1

        except Exception as e:
            self._warn("unable to spool the yara qa matches of %s: %s", job.qa.get("file_name"), e)
            _unlink(file_path)

        finally:
            if job.fd is not None:
                os.close(job.fd)
                job.fd = None

    def _full(self) -> bool:
        if not self.max_jobs:
            return False

        now = time.monotonic()
        if self.counted_at is None or now - self.counted_at >= SPOOL_COUNT_SECONDS:
            self.counted_jobs = count_jobs(self.spool_dir)
            self.counted_at = now

        return self.counted_jobs >= self.max_jobs

    def _warn(self, message: str, *args):
        now = time.monotonic()
        if self.warned_at is None or now - self.warned_at >= WARNING_INTERVAL:
            self.warned_at = now
            logging.warning(message, *args)


#
# recorder side
#

class QARecorder:
    """Runs in the qa recorder process: records the spooled jobs into saq.yara_qa.store."""

    def __init__(self, spool_dir: str):
        self.spool_dir = spool_dir
        self.next_sweep = 0.0
        self.next_depth_log = 0.0

    def _path(self, name: str, suffix: str) -> str:
        return _job_path(self.spool_dir, name, suffix)

    def _names(self, suffix: str) -> list[str]:
        return sorted(name[:-len(suffix)] for name in os.listdir(self.spool_dir) if name.endswith(suffix))

    def drop_interrupted(self):
        """Drops the jobs a previous recorder claimed and never finished."""
        for name in self._names(CLAIMED_SUFFIX):
            logging.warning("dropping yara qa job %s: it was interrupted while being recorded", name)
            _unlink(self._path(name, CLAIMED_SUFFIX))
            # a job that was being put back for a retry still needs its file
            if not os.path.exists(self._path(name, JOB_SUFFIX)):
                _unlink(self._path(name, FILE_SUFFIX))

    def sweep_orphans(self):
        """Removes the files that processes which died while writing a job left behind."""
        jobs = set(self._names(JOB_SUFFIX)) | set(self._names(CLAIMED_SUFFIX))
        cutoff = time.time() - ORPHAN_AGE_SECONDS
        for name in os.listdir(self.spool_dir):
            orphaned = name.endswith(TMP_SUFFIX) or (
                name.endswith(FILE_SUFFIX) and name[:-len(FILE_SUFFIX)] not in jobs)
            if not orphaned:
                continue

            path = os.path.join(self.spool_dir, name)
            try:
                # ctime, not mtime: a hardlink keeps the mtime of the engine's file, but linking
                # it changed the ctime
                if os.stat(path).st_ctime < cutoff:
                    logging.warning("removing orphaned yara qa spool file %s", name)
                    _unlink(path)
            except FileNotFoundError:
                pass

    def process_once(self, should_stop: Callable[[], bool]) -> bool:
        """Records the waiting jobs, oldest first, until there are none left or should_stop()
        returns True. Returns False if it stopped because the database is unreachable."""
        now = time.monotonic()
        if now >= self.next_sweep:
            self.next_sweep = now + ORPHAN_SWEEP_INTERVAL
            self.sweep_orphans()

        names = self._names(JOB_SUFFIX)
        if names and now >= self.next_depth_log:
            self.next_depth_log = now + DEPTH_LOG_INTERVAL
            logging.info("%d yara qa jobs waiting in %s", len(names), self.spool_dir)

        for name in names:
            if should_stop():
                return True

            if not self.process_job(name):
                return False

        return True

    def process_job(self, name: str) -> bool:
        """Records one job. Returns False if the database is unreachable; the matches that were not
        recorded yet then stay in the spool, unless the job ran out of attempts."""
        job_path = self._path(name, JOB_SUFFIX)
        claimed_path = self._path(name, CLAIMED_SUFFIX)
        file_path = self._path(name, FILE_SUFFIX)

        try:
            os.rename(job_path, claimed_path)
        except FileNotFoundError:
            return True

        try:
            with open(claimed_path) as fp:
                job = json.load(fp)

            if job.get("v") != SPOOL_VERSION:
                raise ValueError(f"unsupported version {job.get('v')!r}")

            qa = job["qa"]
            target = QATarget(path=file_path, sha256=qa["sha256"], file_name=qa["file_name"],
                              file_size=qa["file_size"], root_uuid=qa["root_uuid"],
                              observable_uuid=qa["observable_uuid"])
            encoded = job["matches"]
            # back to what YaraScanner.scan_results holds, so the stored record is the same as
            # when the engine stored it
            matches = protocol.decode_matches(encoded)

        except Exception as e:
            logging.error("dropping invalid yara qa job %s: %s", name, e)
            self._remove(name)
            return True

        for index, match in enumerate(matches):
            try:
                result = record_qa_match_or_raise(match, target)
                logging.debug("yara qa match of rule %s on %s: %s", match.get("rule"), target, result.status)

            except TRANSIENT_ERRORS as e:
                attempts = int(job.get("attempts") or 0) + 1
                if attempts >= MAX_ATTEMPTS:
                    logging.error("dropping yara qa job %s after %d attempts: %s", name, attempts, e)
                    self._remove(name)
                    return False

                logging.warning("unable to record yara qa job %s (attempt %d), retrying in %d seconds: %s",
                                name, attempts, DATABASE_RETRY_SECONDS, e)
                # put back what is left. the job is written before the claim is removed, so that a
                # crash in between leaves a job and its file rather than neither
                _write_json(job_path, {**job, "matches": encoded[index:], "attempts": attempts})
                _unlink(claimed_path)
                return False

            except Exception as e:
                logging.error("unable to record yara qa match of rule %s on %s: %s", match.get("rule"), target, e)
                report_exception()

        self._remove(name)
        return True

    def _remove(self, name: str):
        _unlink(self._path(name, CLAIMED_SUFFIX))
        _unlink(self._path(name, FILE_SUFFIX))


def run_recorder(spool_dir: str, ctl_r: int) -> int:
    """The qa recorder process. Stops once its control pipe is readable: the manager wrote to it,
    closed it, or died."""
    os.nice(RECORDER_NICENESS)
    logging.info("yara qa recorder %d recording from %s", os.getpid(), spool_dir)

    recorder = QARecorder(spool_dir)
    recorder.drop_interrupted()

    def should_stop() -> bool:
        readable, _, _ = select.select([ctl_r], [], [], 0)
        return bool(readable)

    delay = 0.0
    while True:
        readable, _, _ = select.select([ctl_r], [], [], delay)
        if readable:
            return 0

        try:
            delay = POLL_INTERVAL if recorder.process_once(should_stop) else DATABASE_RETRY_SECONDS
        except Exception as e:
            log_loop_exception(e, "recording yara qa matches")
            delay = POLL_INTERVAL
