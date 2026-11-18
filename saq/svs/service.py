"""service_svs: runs the queued YARA validations (docs/SVS_VALIDATION.md, *The svs service*), keeps
the Atomic Red Team catalog current (docs/SVS_RUNS.md, *The Atomic Red Team catalog*), moves test
runs on by time, and keeps ATT&CK coverage current (docs/SVS_COVERAGE.md, *Refresh*).

Each worker thread claims a validation (saq.svs.validations.claim), runs the replay
(saq.svs.yara.replay.run_replay) while a heartbeat keeps its lease, and stores the report. The
replay's sandboxed scan is cancelled when the service stops, and the validation goes back to the
queue; when the lease is lost (another worker took over) the scan is cancelled too and its result
dropped. svs.yara.max_concurrent_validations workers run, on the primary node only.

The catalog refresher looks for a new commit of each svs.catalog.repositories checkout every
svs.catalog.refresh_interval_seconds, also on the primary node only (saq.svs.catalog).

The run timer moves test runs whose start timeout or windows have passed every
svs.runs.timer_interval_seconds (saq.svs.runs.run_timers), and expires test hosts' maintenance
windows and closes their alerts (saq.svs.maintenance.run_timers), on the primary node only. Every move is
conditional on the run's state, so a second timer somewhere would change nothing [FR-13].

The coverage refresher recomputes ATT&CK coverage every svs.coverage.refresh_interval_seconds, on the
primary node only (saq.svs.coverage). A refresh holds a lock, so one run by hand never interleaves
with it.
"""

import logging
import threading
from typing import Optional, Type

from saq.configuration.config import get_config, get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import SERVICE_SVS
from saq.database.pool import remove_all_sessions
from saq.database.util.node import is_primary_node
from saq.environment import get_global_runtime_settings
from saq.error.reporting import log_loop_exception
from saq.service import ACEServiceInterface
from saq.svs.actions import retired_pairs
from saq.svs.catalog import refresh_catalog
from saq.svs.constants import COVERAGE_ACTOR
from saq.svs.coverage import refresh_coverage
from saq.svs import maintenance
from saq.svs.runs import run_timers
from saq.svs.service_config import SVSServiceConfig
from saq.svs.validations import (
    Claim,
    LeaseLost,
    claim,
    complete,
    corpus_version,
    engine_fingerprint,
    fail,
    fail_abandoned,
    heartbeat,
    release,
)
from saq.svs.yara.layout import LayoutError
from saq.svs.yara.replay import ReplayCancelled, ReplayError, run_replay


INTERNAL_ERROR = "internal error; see the svs service log"


class ValidationWorker:
    """Claims and runs validations one at a time until stopped."""

    def __init__(self, config: SVSServiceConfig, node: str, shutdown: threading.Event, name: str):
        self.config = config
        self.node = node
        self.shutdown = shutdown
        self.name = name
        self.thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._cancel: Optional[threading.Event] = None

    def start(self):
        self.thread = threading.Thread(target=self.loop, name=self.name, daemon=True)
        self.thread.start()

    def cancel(self):
        """Stops the validation running now, if any."""
        with self._lock:
            if self._cancel is not None:
                self._cancel.set()

    def loop(self):
        while not self.shutdown.is_set():
            ran = False
            try:
                ran = self.run_once()
            except Exception as e:
                log_loop_exception(e, "svs validation worker failed")
            finally:
                remove_all_sessions()

            if not ran:
                self.shutdown.wait(self.config.poll_interval_seconds)

    def run_once(self) -> bool:
        """Runs one validation if one is waiting. Returns whether it did."""
        fail_abandoned(lease_seconds=self.config.lease_seconds, max_attempts=self.config.max_attempts)
        claimed = claim(self.node, lease_seconds=self.config.lease_seconds, max_attempts=self.config.max_attempts)
        if claimed is None:
            return False

        self.execute(claimed)
        return True

    def execute(self, claimed: Claim):
        cancel = threading.Event()
        with self._lock:
            self._cancel = cancel
        if self.shutdown.is_set():
            cancel.set()

        lost = threading.Event()
        done = threading.Event()

        def _keep_lease():
            while not done.wait(self.config.heartbeat_interval_seconds):
                try:
                    alive = heartbeat(claimed)
                except Exception as e:
                    # a failed heartbeat is not a lost lease; the next one may succeed
                    log_loop_exception(e, f"unable to renew the lease on svs validation {claimed.uuid}")
                    continue
                finally:
                    remove_all_sessions()

                if not alive:
                    lost.set()
                    cancel.set()
                    return

        keeper = threading.Thread(target=_keep_lease, name=f"{self.name}-lease", daemon=True)
        keeper.start()
        extra = {"svs_validation": claimed.uuid, "repository": claimed.repository,
                 "base_sha": claimed.base_sha, "head_sha": claimed.head_sha, "attempt": claimed.attempts}
        logging.info("running svs validation %s", claimed.uuid, extra=extra)
        try:
            # taken before the replay reads the corpus, so a change while it runs makes the next
            # request run again
            version, fingerprint = corpus_version(), engine_fingerprint(claimed.repository)
            result = run_replay(claimed.repository, claimed.base_sha, claimed.head_sha, branch=claimed.branch,
                                retired=retired_pairs(), cancel=cancel)
            complete(claimed, result, corpus_version_=version, engine_fingerprint_=fingerprint)
            logging.info("svs validation %s completed in %.0fs", claimed.uuid, result.duration_seconds,
                         extra={**extra, "counts": result.counts, "diffed": result.diffed})
        except ReplayCancelled:
            if lost.is_set():
                logging.warning("svs validation %s was taken over by another worker", claimed.uuid, extra=extra)
            elif release(claimed):
                logging.info("svs validation %s returned to the queue: the service is stopping", claimed.uuid,
                             extra=extra)
        except LeaseLost:
            logging.warning("svs validation %s was taken over by another worker before it completed",
                            claimed.uuid, extra=extra)
        except (ReplayError, LayoutError) as e:
            logging.warning("svs validation %s failed: %s", claimed.uuid, e, extra=extra)
            fail(claimed, str(e))
        except Exception as e:
            log_loop_exception(e, f"svs validation {claimed.uuid} failed")
            fail(claimed, INTERNAL_ERROR)
        finally:
            done.set()
            keeper.join(timeout=5)
            with self._lock:
                self._cancel = None


class CatalogRefresher:
    """Refreshes the Atomic Red Team catalog until stopped."""

    def __init__(self, shutdown: threading.Event):
        self.shutdown = shutdown
        self.thread: Optional[threading.Thread] = None

    def start(self):
        self.thread = threading.Thread(target=self.loop, name="svs-catalog", daemon=True)
        self.thread.start()

    def run_once(self):
        try:
            # a failure of one repository is recorded on its row and logged by refresh_catalog
            refresh_catalog()
        except Exception as e:
            log_loop_exception(e, "svs catalog refresh failed")
        finally:
            remove_all_sessions()

    def loop(self):
        while not self.shutdown.is_set():
            self.run_once()
            self.shutdown.wait(get_config().svs.catalog.refresh_interval_seconds)


class RunTimer:
    """Moves test runs on by time until stopped."""

    def __init__(self, shutdown: threading.Event):
        self.shutdown = shutdown
        self.thread: Optional[threading.Thread] = None

    def start(self):
        self.thread = threading.Thread(target=self.loop, name="svs-runs", daemon=True)
        self.thread.start()

    def run_once(self):
        try:
            # a run that can't be moved is logged by run_timers and retried on the next pass
            run_timers()
        except Exception as e:
            log_loop_exception(e, "svs run timers failed")
        finally:
            remove_all_sessions()

        try:
            maintenance.run_timers()
        except Exception as e:
            log_loop_exception(e, "svs maintenance timers failed")
        finally:
            remove_all_sessions()

    def loop(self):
        while not self.shutdown.is_set():
            self.run_once()
            self.shutdown.wait(get_config().svs.runs.timer_interval_seconds)


class CoverageRefresher:
    """Refreshes ATT&CK coverage until stopped."""

    def __init__(self, shutdown: threading.Event):
        self.shutdown = shutdown
        self.thread: Optional[threading.Thread] = None

    def start(self):
        self.thread = threading.Thread(target=self.loop, name="svs-coverage", daemon=True)
        self.thread.start()

    def run_once(self):
        try:
            # a failed refresh changes nothing and is recorded on svs_coverage_state
            refresh_coverage(COVERAGE_ACTOR)
        except Exception as e:
            log_loop_exception(e, "svs coverage refresh failed")
        finally:
            remove_all_sessions()

    def loop(self):
        while not self.shutdown.is_set():
            self.run_once()
            self.shutdown.wait(get_config().svs.coverage.refresh_interval_seconds)


class SVSService(ACEServiceInterface):

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return SVSServiceConfig

    def __init__(self):
        self.shutdown = threading.Event()
        self.workers: list[ValidationWorker] = []
        self.catalog: Optional[CatalogRefresher] = None
        self.runs: Optional[RunTimer] = None
        self.coverage: Optional[CoverageRefresher] = None

    def _workers(self) -> list[ValidationWorker]:
        config = get_service_config(SERVICE_SVS)
        node = get_global_runtime_settings().saq_node
        return [ValidationWorker(config, node, self.shutdown, f"svs-validation-{index}")
                for index in range(get_config().svs.yara.max_concurrent_validations)]

    def start(self):
        if not is_primary_node():
            # the queue, the catalog and the runs are shared; one node runs them
            logging.info("svs validations, the catalog refresh, the run timers and the coverage refresh run on the "
                         "primary node only; this service stays idle")
            return

        self.workers = self._workers()
        for worker in self.workers:
            worker.start()

        self.catalog = CatalogRefresher(self.shutdown)
        self.catalog.start()

        self.runs = RunTimer(self.shutdown)
        self.runs.start()

        self.coverage = CoverageRefresher(self.shutdown)
        self.coverage.start()

    def wait_for_start(self, timeout: float = 5) -> bool:
        return True

    def start_single_threaded(self):
        """Refreshes the catalog, moves the runs and refreshes coverage once, and runs every waiting
        validation, one at a time, then returns. The service is finished then, so wait() returns too (`ace service start
        --single-threaded svs` exits)."""
        try:
            CatalogRefresher(self.shutdown).run_once()
            RunTimer(self.shutdown).run_once()
            CoverageRefresher(self.shutdown).run_once()
            worker = self._workers()[0]
            while not self.shutdown.is_set():
                try:
                    if not worker.run_once():
                        break
                finally:
                    remove_all_sessions()
        finally:
            self.shutdown.set()

    def stop(self):
        self.shutdown.set()
        for worker in self.workers:
            worker.cancel()

    def wait(self):
        # the service runs until it is stopped, idle or not: `ace service start` reads a wait()
        # that returns as the service having finished. It bounds this wait once it stops us
        self.shutdown.wait()
        for worker in self.workers:
            if worker.thread is not None:
                worker.thread.join()
        for component in (self.catalog, self.runs, self.coverage):
            if component is not None and component.thread is not None:
                component.thread.join()
