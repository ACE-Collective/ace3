import logging
from multiprocessing import cpu_count
import signal
from typing import Optional

import psutil
from saq.engine.configuration_manager import ConfigurationManager
from saq.engine.enums import EngineExecutionMode, WorkerManagerState, WorkerStatus
from saq.engine.node_manager.node_manager_interface import NodeManagerInterface
from saq.engine.tracking import TrackingReader
from saq.engine.worker import Worker
from saq.util.process import kill_process_tree



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

        # wait for all workers to start
        for worker in self.workers:
            worker.wait_for_start()

        logging.info("workers initialized")

    def check_workers(self):
        """Check all workers and restart any that need to be restarted."""
        dead_workers = []
        for worker in self.workers:
            status = self.check(worker)
            if status == WorkerStatus.DEAD:
                dead_workers.append(worker)

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
                return WorkerStatus.DEAD

        # what is this worker doing? read once and use it for both the timeout check and
        # the memory limit log lines below, so the tick costs one small read per worker
        record = self.tracking_reader.read_worker_record(worker.name)

        # is the process running?
        # is it taking too long to analyze something?
        if worker.analysis_has_timed_out(record):
            logging.warning(f"worker {worker} analysis has timed out")
            try:
                kill_process_tree(worker.process.pid, signal.SIGKILL)
            except Exception as e:
                logging.warning(f"unable to kill process {worker.process}: {e}")

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
                kill_process_tree(worker.process.pid, signal.SIGKILL)
                return WorkerStatus.DEAD

            elif memory.rss > self.config.memory_limit_warning:
                logging.warning(
                    f"worker {worker} is using too much memory "
                    f"on {record if record else 'unknown work'}: {memory}"
                )

        except Exception as e:
            logging.error(f"unable to check memory of worker {worker}: {e}")

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

        #
        # this is a bit hairy
        #

        try:
            #
            # XXX this does not seem to be able to handle the case
            # when a process is killed by a signal
            #

            if dead_worker.process is not None:
                dead_worker.process.close()

        except Exception as e:
            logging.info(f"unable to close process {dead_worker.process}: {e}")

            try:
                # you have to do this to close *both* pipes opened
                if dead_worker.process is not None:
                    logging.debug(f"finalizing {dead_worker.process}")
                    dead_worker.process._popen.finalizer() # pyright: ignore
                    logging.debug(f"finished finalizing {dead_worker.process}")
            except Exception as e:
                logging.error(f"unable to finalize process: {e}")

    def restart_workers(self):
        """Restart all workers."""
        logging.info("restarting all workers")
        
        # stop all workers
        for worker in self.workers:
            worker.controlled_shutdown()

        # start all workers
        for worker in self.workers:
            worker.start(execution_mode=self.execution_mode)

        # wait for all workers to start
        for worker in self.workers:
            worker.wait_for_start()

    def immediate_shutdown(self):
        """Shutdown all workers immediately."""
        logging.info(f"shutting down {len(self.workers)} workers immediately")

        self.set_state(WorkerManagerState.SHUTTING_DOWN)

        for worker in self.workers:
            worker.immediate_shutdown()
        
        # make sure all the processes exit
        for worker in self.workers:
            worker.wait()

        logging.info("all workers shut down")

    def controlled_shutdown(self):
        """Shutdown all workers after they have finished processing all work."""
        logging.info("shutting down all workers")

        self.set_state(WorkerManagerState.SHUTTING_DOWN)

        for worker in self.workers:
            worker.controlled_shutdown()

        # make sure all the processes exit
        for worker in self.workers:
            worker.wait()

        logging.info("all workers shut down")

