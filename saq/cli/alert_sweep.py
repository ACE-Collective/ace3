"""Runs a per-alert action over every alert on this node without holding the whole set in memory.

The alerts are walked by primary key in fixed size batches (keyset pagination), each alert is
loaded by its id, and its analysis tree and the ORM session are released as soon as it has been
handled -- so memory and database cost stay flat no matter how many alerts the node holds.

With more than one worker the batches are fanned out to forked processes, at most two per worker
in flight. Batches are collected oldest first, so the id of the last batch collected is a resume
point: every alert at or below it has been handled, whatever order the workers finished in.
"""

import logging
import signal
import time
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import Future, ProcessPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from itertools import islice
from typing import Optional

from sqlalchemy import func, select

from saq.database.model import Alert
from saq.database.pool import get_db
from saq.environment import ACE_MP_CONTEXT, get_global_runtime_settings

DEFAULT_BATCH_SIZE = 100

# how often (in alerts handled) a progress line is logged
PROGRESS_INTERVAL = 1000

# each worker process is replaced after this many batches, which bounds whatever a long
# lived process accumulates (ProcessPoolExecutor cannot recycle forked workers itself)
BATCHES_PER_WORKER_PROCESS = 50

AlertAction = Callable[[Alert], None]


@dataclass
class BatchResult:
    processed: int = 0
    failed: int = 0
    # deleted between being paged and being handled -- not a failure
    vanished: int = 0


@dataclass
class SweepResult:
    total: int
    processed: int = 0
    failed: int = 0
    vanished: int = 0
    # every alert with an id at or below this has been handled
    resume_after_id: Optional[int] = None
    # False when the sweep was interrupted or its worker pool died
    completed: bool = False

    @property
    def done(self) -> int:
        return self.processed + self.failed + self.vanished


def _node_alert_conditions(after_id: int, insert_range: Optional[tuple[datetime, datetime]]) -> list:
    conditions = [Alert.location == get_global_runtime_settings().saq_node, Alert.id > after_id]
    if insert_range:
        start, end = insert_range
        conditions.extend([Alert.insert_date >= start, Alert.insert_date <= end])

    return conditions


def count_node_alerts(after_id: int = 0, insert_range: Optional[tuple[datetime, datetime]] = None) -> int:
    """Returns how many alerts on this node iter_node_alert_id_batches() would yield."""
    try:
        return get_db().scalar(select(func.count(Alert.id)).where(*_node_alert_conditions(after_id, insert_range)))
    finally:
        get_db().commit()


def iter_node_alert_id_batches(after_id: int = 0, insert_range: Optional[tuple[datetime, datetime]] = None,
                               batch_size: int = DEFAULT_BATCH_SIZE) -> Iterator[list[int]]:
    """Yields the ids of the alerts on this node with an id above after_id (and inserted within
    insert_range, if given), in ascending order, batch_size at a time."""
    last_id = after_id
    while True:
        try:
            alert_ids = list(get_db().scalars(
                select(Alert.id)
                .where(*_node_alert_conditions(last_id, insert_range))
                .order_by(Alert.id)
                .limit(batch_size)))
        finally:
            # do not hold a read snapshot open across a run that takes hours
            get_db().commit()

        if not alert_ids:
            return

        yield alert_ids

        if len(alert_ids) < batch_size:
            return

        last_id = alert_ids[-1]


def resolve_alert_ids_by_storage_dir(storage_dirs: list[str]) -> tuple[list[int], list[str]]:
    """Returns the ids of the alerts stored in the given directories (ascending) and the
    directories that no alert is stored in."""
    if not storage_dirs:
        return [], []

    try:
        ids_by_storage_dir = dict(get_db().execute(
            select(Alert.storage_dir, Alert.id).where(Alert.storage_dir.in_(storage_dirs))).all())
    finally:
        get_db().commit()

    missing = [storage_dir for storage_dir in storage_dirs if storage_dir not in ids_by_storage_dir]
    return sorted(set(ids_by_storage_dir.values())), missing


def process_alert_batch(alert_ids: list[int], action: AlertAction) -> BatchResult:
    """Loads each alert and its analysis tree and calls action(alert) on it. A failure is
    logged and counted, and never stops the batch."""
    result = BatchResult()
    try:
        for alert_id in alert_ids:
            alert = None
            try:
                alert = get_db().get(Alert, alert_id)
                if alert is None:
                    logging.warning("alert id %s no longer exists", alert_id)
                    result.vanished += 1
                    continue

                if not alert.load():
                    logging.error("unable to load %s", alert.storage_dir)
                    result.failed += 1
                    continue

                action(alert)
                result.processed += 1

            except Exception as e:
                get_db().rollback()
                logging.error("%s failed on alert id %s: %s (%s)", action.__name__, alert_id, e, type(e))
                result.failed += 1

            finally:
                if alert is not None:
                    alert.unload()

    finally:
        # drops the identity map along with the transaction
        get_db().close()

    return result


class _SweepTracker:
    def __init__(self, result: SweepResult, verb: str, show_resume: bool):
        self.result = result
        self.verb = verb
        self.show_resume = show_resume
        self.start = time.monotonic()
        self.next_report = PROGRESS_INTERVAL

    def record(self, batch: BatchResult, last_id: int):
        self.result.processed += batch.processed
        self.result.failed += batch.failed
        self.result.vanished += batch.vanished
        self.result.resume_after_id = last_id

        if self.result.done >= self.next_report:
            self.next_report = self.result.done + PROGRESS_INTERVAL
            self.log_progress()

    def resume_hint(self) -> str:
        if not self.show_resume or self.result.resume_after_id is None:
            return ""

        return f"; resume with --after-id {self.result.resume_after_id}"

    def log_progress(self):
        elapsed = max(time.monotonic() - self.start, 0.001)
        logging.info("%s %d/%d alerts (%d failed, %.1f/s)%s", self.verb, self.result.done, self.result.total,
                     self.result.failed, self.result.done / elapsed, self.resume_hint())


def _ignore_sigint():
    # Ctrl-C reaches the whole process group; the parent decides how the pool stops
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def _collect_oldest(pending: deque[tuple[int, Future]], tracker: _SweepTracker):
    last_id, future = pending.popleft()
    tracker.record(future.result(), last_id)


def _run_in_pool(batches: Iterable[list[int]], action: AlertAction, workers: int, tracker: _SweepTracker):
    batch_iterator = iter(batches)
    while True:
        submitted = False
        executor = ProcessPoolExecutor(max_workers=workers, mp_context=ACE_MP_CONTEXT, initializer=_ignore_sigint)
        try:
            pending: deque[tuple[int, Future]] = deque()
            for batch in islice(batch_iterator, workers * BATCHES_PER_WORKER_PROCESS):
                submitted = True
                pending.append((batch[-1], executor.submit(process_alert_batch, batch, action)))
                while len(pending) >= workers * 2:
                    _collect_oldest(pending, tracker)

            while pending:
                _collect_oldest(pending, tracker)

        finally:
            # on an interrupt the workers finish the batch they are on; nothing queued is started
            executor.shutdown(wait=True, cancel_futures=True)

        if not submitted:
            return


def run_alert_sweep(batches: Iterable[list[int]], action: AlertAction, total: int, workers: int = 1,
                    verb: str = "processed", after_id: Optional[int] = None) -> SweepResult:
    """Calls action(alert) on every alert id in batches, in-process when workers is 1 and in
    that many forked processes otherwise. after_id is where an --all sweep started; pass None
    when the batches are not an ascending walk of the node's alerts, which leaves the resume
    hint out of the log."""
    result = SweepResult(total=total, resume_after_id=after_id)
    tracker = _SweepTracker(result, verb, show_resume=after_id is not None)
    logging.info("%s: %d alerts to go through with %d worker(s)", verb, total, workers)

    try:
        if workers == 1:
            for batch in batches:
                tracker.record(process_alert_batch(batch, action), batch[-1])
        else:
            _run_in_pool(batches, action, workers, tracker)

        result.completed = True

    except KeyboardInterrupt:
        logging.error("interrupted after %d of %d alerts%s", result.done, total, tracker.resume_hint())

    except Exception as e:
        logging.error("sweep stopped after %d of %d alerts: %s (%s)%s", result.done, total, e, type(e),
                      tracker.resume_hint())

    logging.info("%s %d alerts, %d failed, %d no longer exist", verb, result.processed, result.failed,
                 result.vanished)
    return result
