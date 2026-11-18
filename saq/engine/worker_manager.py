import logging
import os
import signal
import time
from multiprocessing import cpu_count
from typing import Optional

import psutil
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.enums import EngineExecutionMode, WorkerManagerState, WorkerStatus
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.tracking import TrackingReader
from saq.engine.worker import Worker
from saq.error.reporting import log_loop_exception
from saq.sandbox.launcher import set_child_subreaper
from saq.shutdown import get_shutdown_coordinator, is_shutting_down

# how long kill_adopted() keeps at it: only a process stuck in the kernel outlives SIGKILL for long
ADOPTED_KILL_SECONDS = 5


def _reap(pid: int) -> bool:
    """Reap pid if it has exited. True when it is gone."""
    try:
        reaped, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return True  # it is not a child of this process any more

    return reaped == pid


class WorkerManager:
    """Manages the workers for the engine."""
    
    def __init__(
        self, 
        configuration_manager: ConfigurationManager, 
        node_manager: NodeManagerInterface
    ):
        self.configuration_manager = configuration_manager
        self.config = self.configuration_manager.config
        self.node_manager = node_manager
        self.workers: list[Worker] = []
        self.state = WorkerManagerState.INITIALIZING

        # reads what each worker wrote about the analysis it is running -- see
        # saq/engine/tracking.py
        self.tracking_reader = TrackingReader()

        # the execution mode the workers were started in
        # replacement workers are started in the same mode (see restart_worker)
        self.execution_mode = EngineExecutionMode.NORMAL

        # set while this process adopts the orphans of the workers' descendants (see become_subreaper)
        self.subreaper = False
        # this process's children when it became a subreaper, which it did not adopt: a test runs the engine in a
        # process that may have started some of its own
        self.own_children: set[int] = set()

    def set_state(self, state: WorkerManagerState):
        """Sets the state of the worker manager."""
        if state != self.state:
            self.state = state
            logging.info(f"worker manager state set to {state}")

    def add_worker(self, name: str, idle_timeout_max: int, analysis_mode_priority: Optional[str] = None) -> Worker:
        """Adds a worker for the given mode."""
        worker = Worker(
            name=name,
            configuration_manager=self.configuration_manager,
            node_manager=self.node_manager,
            idle_timeout_max=idle_timeout_max,
            analysis_mode_priority=analysis_mode_priority,
        )
        self.workers.append(worker)
        return worker

    def initialize_workers(self):
        """Initialize workers based on configuration."""
        logging.info("initializing workers")

        # if we are in single threaded mode, we only need one worker
        if self.config.single_threaded_mode:
            self.add_worker(
                name="any-0",
                idle_timeout_max=5,
                analysis_mode_priority=None
            )

        # load the workers
        # the configuration defines how many workers each analysis mode has
        # NOTE that workers can do work for other anaysis modes as well
        for mode in self.config.analysis_pools.keys():
            pool_size = self.config.analysis_pools[mode]
            logging.debug(f"adding {pool_size} workers for analysis mode {mode}")
            for i in range(pool_size):
                self.add_worker(
                    name=f"{mode}-{i}",
                    idle_timeout_max=max(pool_size, 5), 
                    analysis_mode_priority=mode
                )

        # do we NOT have any defined analysis pools?
        if len(self.workers) == 0:
            # create a default pool of workers based on the number of CPUs
            pool_count = cpu_count()
            if (
                self.config.pool_size_limit is not None
                and pool_count > self.config.pool_size_limit
            ):
                pool_count = self.config.pool_size_limit

            logging.info(
                "no analysis pools defined -- defaulting to {} workers assigned to any pool".format(
                    pool_count
                )
            )

            for i in range(pool_count):
                self.add_worker(
                    name=f"any-{i}",
                    idle_timeout_max=pool_count
                )

    def start_workers(self, execution_mode: EngineExecutionMode):
        """Starts the workers."""

        if not self.workers:
            logging.error("no workers to start (forgot to call initialize_workers?)")
            return

        # remember the mode so that any worker we restart comes back in the same mode
        self.execution_mode = execution_mode

        # pick up anything a previous incarnation of this manager left behind. a record that
        # still names a module was never cleared by the worker that owned it, so the module
        # in it is what killed that worker and must not run again
        pending = self.tracking_reader.recover_pending_failures()
        if pending:
            logging.warning(
                "recovered %d unresolved analysis failure(s) from the previous engine", len(pending)
            )

        self.become_subreaper()

        # start the workers, handing each one a leftover failure to resolve. dispatch is
        # deliberately not matched on worker name: a pool that shrank since the last run
        # would strand every record whose worker no longer exists, and the record is fully
        # self describing (root_uuid + storage_dir) so any worker can apply it
        for worker in self.workers:
            worker.start(
                execution_mode=execution_mode,
                pending_failure=pending.pop() if pending else None,
            )

        if pending:
            # more leftovers than workers. their files are still there, so the next restart
            # picks them up again rather than losing them -- but say so, because a backlog
            # this size means something is repeatedly killing workers
            logging.warning(
                "%d analysis failure(s) could not be dispatched to a worker at startup", len(pending)
            )

        # wait for all workers to start. a worker that cannot start (its modules failed to
        # load, say) would fail the same way if restarted, so the engine fails to start
        # rather than waiting on it or running without it
        failed = [worker.name for worker in self.workers if not worker.wait_for_start()]
        if failed:
            if is_shutting_down():
                logging.info("shutdown requested while the workers were starting")
                return

            self.immediate_shutdown()
            raise RuntimeError(f"workers did not start: {', '.join(failed)}")

        logging.info("workers initialized")

    def check_workers(self):
        """Check all workers and restart any that need to be restarted."""
        dead_workers = []
        for worker in self.workers:
            status = self.check(worker)
            if status == WorkerStatus.DEAD:
                dead_workers.append(worker)

        if self.subreaper:
            if dead_workers:
                # what they left running outside their process groups
                self.kill_adopted()
            else:
                self.reap_adopted()

        for worker in dead_workers:
            self.restart_worker(worker)

    def check(self, worker: Worker) -> WorkerStatus:
        """Makes sure the process is running and restarts it if it is not."""

        if worker.process is None:
            # this should never happen
            logging.error(f"worker {worker} process is None")
            return WorkerStatus.DEAD

        # is the worker process dead?
        if worker.process is not None:
            worker.process.join(0)
            if worker.process.exitcode is not None:
                logging.debug(
                    f"worker {worker} process {worker.process.pid} exitcode = {worker.process.exitcode}"
                )
                # a worker that died on its own (the analysis module monitor's os._exit, a crash, the OOM
                # killer) leaves whatever its modules started still running, in its process group
                worker.kill()
                return WorkerStatus.DEAD

        # what is this worker doing? read once and use it for both the timeout check and
        # the memory limit log lines below, so the tick costs one small read per worker
        record = self.tracking_reader.read_worker_record(worker.name)

        # is the process running?
        # is it taking too long to analyze something?
        if worker.analysis_has_timed_out(record):
            logging.warning(f"worker {worker} analysis has timed out")
            worker.kill()
            return WorkerStatus.DEAD

        # is it using too much memory?
        try:
            worker_process = psutil.Process(pid=worker.process.pid)
            memory = worker_process.memory_info()
            if memory.rss > self.config.memory_limit_kill:
                logging.error(
                    f"worker {worker} used too much memory "
                    f"on {record if record else 'unknown work'}: {memory} KILLING"
                )
                worker.kill()
                return WorkerStatus.DEAD

            elif memory.rss > self.config.memory_limit_warning:
                logging.warning(
                    f"worker {worker} is using too much memory "
                    f"on {record if record else 'unknown work'}: {memory}"
                )

        except psutil.NoSuchProcess:
            # the worker exited between the exitcode check above and this call. routine
            # during shutdown, when every worker is on its way out and this check runs on
            # each poll -- at ERROR it produced a line per worker per poll, which is the
            # kind of noise this whole path exists to avoid
            logging.debug("worker %s exited while being checked", worker)
        except Exception as e:
            log_loop_exception(e, f"unable to check memory of worker {worker}")

        return WorkerStatus.OK

    def restart_worker(self, dead_worker: Worker):
        """Restarts a worker."""

        logging.info(
            "detected death of process {} pid {}".format(
                dead_worker.process, dead_worker.process.pid if dead_worker.process else 'unknown'
            )
        )

        # what was it doing when it died? the record moves out of the worker's own file and
        # into the pending directory right away, so the replacement (which reuses the name)
        # can track its next root without touching the failure we still owe somebody. it
        # stays there until the worker that applies it deletes it
        pending_failure = self.tracking_reader.claim_failure(dead_worker.name)
        if pending_failure is not None:
            logging.warning("worker %s died while running %s", dead_worker.name, pending_failure)

        # remove the worker from the list
        self.workers.remove(dead_worker)

        # add a new worker based on the old worker
        new_worker = self.add_worker(
            name=dead_worker.name,
            idle_timeout_max=dead_worker.idle_timeout_max,
            analysis_mode_priority=dead_worker.analysis_mode_priority
        )

        # start the worker in the same mode the rest of the pool is running in
        new_worker.start(execution_mode=self.execution_mode, pending_failure=pending_failure)

        # release the dead process's pipes. it has been reaped unless a kill did not take
        # effect within Worker.kill()'s join, which leaves a process stuck in the kernel
        if dead_worker.process is not None:
            try:
                dead_worker.process.close()
            except ValueError as e:
                logging.warning("unable to close process %s of worker %s: %s", dead_worker.process.pid,
                                dead_worker.name, e, extra={"worker_name": dead_worker.name})

    def immediate_shutdown(self):
        """Shutdown all workers immediately, abandoning in-flight analysis."""
        logging.info(f"shutting down {len(self.workers)} workers immediately")

        self.set_state(WorkerManagerState.SHUTTING_DOWN)

        for worker in self.workers:
            worker.immediate_shutdown()

        self.supervise_shutdown()

    def controlled_shutdown(self):
        """Shutdown all workers after they have finished processing all work."""
        logging.info("shutting down all workers")

        self.set_state(WorkerManagerState.SHUTTING_DOWN)

        for worker in self.workers:
            worker.controlled_shutdown()

        self.supervise_shutdown()

    def supervise_shutdown(self, poll_interval: float = 0.25):
        """Wait for every worker to exit, against one shared deadline.

        This replaces a per-worker 60 second join taken one worker at a time. With a pool
        of N workers that gave a worst case of N x 60 seconds, far past any container
        stop grace period, so the pool never actually finished shutting down before docker
        SIGKILLed the whole thing.

        Two things matter here beyond the shared budget:

        - workers are polled together, so slow ones overlap instead of queueing;
        - the timeout and memory watchdog keeps running throughout. That watchdog is what
          catches an analysis module stuck in a CPU loop, and it used to stop running the
          moment the controller loop broke for shutdown -- precisely when a stuck module
          is most likely to be what is holding everything up.
        """
        coordinator = get_shutdown_coordinator()

        # leave headroom for the caller to release locks and mark the node stopped after
        # this returns; those steps are what keep the logs quiet on the peers
        budget = max(1.0, coordinator.deadline_remaining() * 0.5)
        deadline = time.monotonic() + budget

        logging.info("waiting up to %.1fs for %d workers to exit", budget, len(self.workers))

        while time.monotonic() < deadline:
            alive = [w for w in self.workers if w.is_alive()]
            if not alive:
                break

            # keep enforcing analysis timeouts and memory limits while we wait
            for worker in alive:
                try:
                    self.check(worker)
                except Exception as e:
                    logging.debug("error checking worker %s during shutdown: %s", worker, e)

            time.sleep(poll_interval)

        for worker in self.workers:
            if worker.is_alive():
                # it has ignored the shutdown event past the budget
                logging.warning("worker %s did not exit in time - killing", worker.name)

            # also for one that exited: is_alive() reaped it, so check() never killed what it left in its group
            worker.kill()

        if self.subreaper:
            self.kill_adopted()
            self.stop_adopting()

        logging.info("all workers shut down")

    def become_subreaper(self):
        """Have the orphans of every process the workers start reparented to this process, wherever in the process
        tree they moved to, instead of to the container's init, which reaps them but never kills them.

        A worker leads a process group, and Worker.kill() kills that group. Groups do not nest, so a process an
        analysis module starts in a session or group of its own has left it; once its worker has died it is adopted
        here, and kill_adopted() kills it."""
        try:
            self.own_children = {child.pid for child in psutil.Process().children()}
            set_child_subreaper(True)
        except Exception:
            # the workers' process groups still contain what stays in them
            logging.exception("unable to make the engine controller (pid %s) a child subreaper", os.getpid(),
                              extra={"pid": os.getpid()})
            return

        self.subreaper = True
        logging.info("the engine controller (pid %s) adopts what the workers' processes orphan", os.getpid())

    def stop_adopting(self):
        """Have orphans reparented to init again. The engine can run in a process that outlives it (a test run)."""
        try:
            set_child_subreaper(False)
        except Exception:
            logging.exception("unable to stop the engine controller (pid %s) being a child subreaper", os.getpid(),
                              extra={"pid": os.getpid()})

        self.subreaper = False

    def _adopted_children(self) -> list[psutil.Process]:
        """This process's children that are neither workers nor children it had before it became a subreaper."""
        known = self.own_children | {worker.process.pid for worker in self.workers
                                     if worker.process is not None and worker.process.pid is not None}
        return [child for child in psutil.Process().children() if child.pid not in known]

    def reap_adopted(self):
        """Reap the adopted processes that have exited, which nothing else waits for. Every controller second, by
        pid, which leaves reaping the workers to multiprocessing. Never raises."""
        try:
            for child in self._adopted_children():
                if _reap(child.pid):
                    logging.debug("reaped adopted process %s", child.pid)
        except Exception as e:
            log_loop_exception(e, "unable to reap the processes the engine controller adopted")

    def kill_adopted(self):
        """Kill and reap every process this process adopted, and everything those started. After a worker has died
        and at shutdown: what a dead worker left running outside its process group has nothing else to stop it.
        What a live worker's processes orphaned is adopted too, and is killed with it. Never raises: it runs on the
        supervision and shutdown paths."""
        try:
            killed = self._kill_adopted()
        except Exception:
            # not log_loop_exception: this is no loop failing on peers that are stopping, and at shutdown
            # supervise_shutdown sweeps only once
            logging.exception("unable to kill the processes the engine controller adopted")
            return

        if killed:
            # not their command lines: a module can pass a secret on one (an archive password to 7z)
            logging.warning("killed %d processes the engine controller adopted: %s", len(killed),
                            ", ".join(killed.values()), extra={"killed_pids": sorted(killed)})

    def _kill_adopted(self) -> dict[int, str]:
        """Returns what it killed, as pid -> "pid name"."""
        killed: dict[int, str] = {}
        give_up = time.monotonic() + ADOPTED_KILL_SECONDS
        while True:
            # a killed process's children are adopted when it dies, so this goes on until no adopted process is left
            live = [child for child in self._adopted_children() if not _reap(child.pid)]
            if not live:
                return killed

            if time.monotonic() > give_up:
                logging.error("%d processes the engine controller adopted survived being killed: %s", len(live),
                              ", ".join(str(child.pid) for child in live),
                              extra={"pids": [child.pid for child in live]})
                return killed

            processes = []
            for child in live:
                processes.append(child)
                try:
                    processes.extend(child.children(recursive=True))
                except psutil.NoSuchProcess:
                    pass  # it exited after the listing

            # stopped first, so that none of them can fork while the rest are being killed. Named before they are
            # killed, because afterwards nothing is left to say what they were
            names = {}
            for process in processes:
                try:
                    names[process.pid] = f"{process.pid} {process.name()}"
                    process.send_signal(signal.SIGSTOP)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass  # it exited, or it is left to the survivors' error above

            for process in processes:
                try:
                    process.kill()
                    killed.setdefault(process.pid, names.get(process.pid, str(process.pid)))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass  # as above

            time.sleep(0.01)

