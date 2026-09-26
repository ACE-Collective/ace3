"""Runs the scheduled maintenance tasks in etc/cron/<cadence>/, run-parts style.

Each cadence (hourly, daily, weekly) is a directory of executables, one per logical task. The
core tasks live in $SAQ_HOME/etc/cron/<cadence>/ and every enabled integration may add its own
in <integration dir>/etc/cron/<cadence>/. All tasks for a cadence run in parallel, at most
service_cron.max_parallel_tasks at a time (the cpu count when unset), so tasks within a cadence
are unordered: steps that depend on each other belong in the same script.

Every task runs through bin/run-cron-job, which gives it its own data/logs/<slug>-<date>.log
and its own structured outcome record on the fluent-bit "cron-jobs" tag. See docs/CRON.md.
"""

import logging
import os
import signal
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional

from saq.configuration.config import get_service_config
from saq.constants import SERVICE_CRON
from saq.environment import get_base_dir
from saq.integration.integration_manager import is_integration_enabled
from saq.integration.integration_util import get_integration_name_from_path, get_valid_integration_dirs

CRON_CADENCES = ("hourly", "daily", "weekly")

# the source of a task shipped with ACE itself
CORE_SOURCE = "core"

# files in a cadence directory that are never run, even when executable
IGNORED_SUFFIXES = ("~", ".bak", ".orig", ".disabled", ".md")

# the exit code recorded for a task whose wrapper could not be started (same as bin/run-cron-job)
EXIT_CODE_UNLAUNCHABLE = 127


@dataclass(frozen=True)
class CronTask:
    name: str
    path: str
    # CORE_SOURCE or the name of the integration that provides the task
    source: str
    # names the task's log file and the "job" field of its outcome record
    slug: str


@dataclass(frozen=True)
class CronTaskResult:
    task: CronTask
    # None when the task was never started because of a shutdown
    exit_code: Optional[int]
    duration_seconds: float

    @property
    def skipped(self) -> bool:
        return self.exit_code is None


def get_cron_dir(base_dir: str, cadence: str) -> str:
    return os.path.join(base_dir, "etc", "cron", cadence)


def is_runnable_task(path: str) -> bool:
    """Returns True if the file at path is a task that should be run."""
    name = os.path.basename(path)
    if name.startswith(".") or name.endswith(IGNORED_SUFFIXES):
        return False

    if not os.path.isfile(path):
        return False

    if not os.access(path, os.X_OK):
        logging.debug(f"skipping cron task {path}: not executable")
        return False

    return True


def _tasks_in_dir(cron_dir: str, cadence: str, source: str) -> list[CronTask]:
    if not os.path.isdir(cron_dir):
        return []

    tasks = []
    for name in sorted(os.listdir(cron_dir)):
        path = os.path.join(cron_dir, name)
        if not is_runnable_task(path):
            continue

        if source == CORE_SOURCE:
            slug = f"{cadence}-{name}"
        else:
            slug = f"{cadence}-{source}-{name}"

        tasks.append(CronTask(name=name, path=path, source=source, slug=slug))

    return tasks


def discover_tasks(cadence: str) -> list[CronTask]:
    """Returns every task to run for the given cadence: the core tasks first, then the tasks of
    each enabled integration, sorted by integration name."""
    if cadence not in CRON_CADENCES:
        raise ValueError(f"invalid cron cadence {cadence!r}: must be one of {', '.join(CRON_CADENCES)}")

    tasks = _tasks_in_dir(get_cron_dir(get_base_dir(), cadence), cadence, CORE_SOURCE)

    integration_tasks = []
    for integration_dir in get_valid_integration_dirs():
        integration_name = get_integration_name_from_path(integration_dir)
        if not is_integration_enabled(integration_name):
            continue

        integration_tasks.extend(_tasks_in_dir(get_cron_dir(integration_dir, cadence), cadence, integration_name))

    integration_tasks.sort(key=lambda task: (task.source, task.name))
    return tasks + integration_tasks


def get_max_parallel_tasks(max_parallel: Optional[int] = None) -> int:
    """Returns how many tasks may run at once: the argument, else service_cron.max_parallel_tasks,
    else the cpu count."""
    if max_parallel is not None:
        return max_parallel

    configured = get_service_config(SERVICE_CRON).max_parallel_tasks
    if configured is not None:
        return configured

    return os.cpu_count() or 1


class CronTaskRunner:
    """Runs a set of tasks in parallel. A shutdown signal stops new tasks from starting and is
    forwarded to the ones already running (bin/run-cron-job passes it on to the task itself)."""

    def __init__(self, tasks: list[CronTask], max_parallel: int):
        self.tasks = tasks
        self.max_parallel = max_parallel
        self.shutdown_requested = threading.Event()
        self._lock = threading.Lock()
        self._running: set[subprocess.Popen] = set()

    def run_task(self, task: CronTask) -> CronTaskResult:
        start = time.monotonic()
        with self._lock:
            if self.shutdown_requested.is_set():
                return CronTaskResult(task=task, exit_code=None, duration_seconds=0.0)

            try:
                proc = subprocess.Popen(
                    [os.path.join(get_base_dir(), "bin", "run-cron-job"), task.slug, task.path],
                    stdin=subprocess.DEVNULL,
                )
            except OSError as e:
                # one task that cannot start must not take the rest of the cadence down with it
                print(f"task {task.slug}: unable to execute: {e}", flush=True)
                return CronTaskResult(task=task, exit_code=EXIT_CODE_UNLAUNCHABLE, duration_seconds=0.0)

            self._running.add(proc)

        try:
            exit_code = proc.wait()
        finally:
            with self._lock:
                self._running.discard(proc)

        return CronTaskResult(task=task, exit_code=exit_code, duration_seconds=time.monotonic() - start)

    def request_shutdown(self, signum: int = signal.SIGTERM):
        with self._lock:
            self.shutdown_requested.set()
            for proc in self._running:
                try:
                    proc.send_signal(signum)
                except Exception:
                    pass

    def run(self) -> list[CronTaskResult]:
        def _handle_signal(signum, frame):
            self.request_shutdown(signum)

        previous = {}
        for signum in (signal.SIGTERM, signal.SIGINT):
            try:
                previous[signum] = signal.signal(signum, _handle_signal)
            except ValueError:
                # not the main thread -- signal forwarding is not available
                pass

        results = []
        try:
            with ThreadPoolExecutor(max_workers=self.max_parallel, thread_name_prefix="cron-task") as executor:
                futures = [executor.submit(self.run_task, task) for task in self.tasks]
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)
                    if result.skipped:
                        print(f"task {result.task.slug} ({result.task.source}) skipped: shutting down", flush=True)
                    else:
                        print(
                            f"task {result.task.slug} ({result.task.source}) exit {result.exit_code} "
                            f"in {result.duration_seconds:.1f}s",
                            flush=True,
                        )
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)

        return results


def run_tasks(cadence: str, max_parallel: Optional[int] = None) -> int:
    """Runs every task for the cadence. Returns 0 if every task ran and succeeded, 1 otherwise."""
    tasks = discover_tasks(cadence)
    limit = get_max_parallel_tasks(max_parallel)
    print(f"running {len(tasks)} {cadence} tasks, at most {limit} at a time", flush=True)

    results = CronTaskRunner(tasks, limit).run()

    exit_code = 0

    failed = [result for result in results if not result.skipped and result.exit_code != 0]
    if failed:
        print(f"{len(failed)} of {len(results)} {cadence} tasks failed: {', '.join(r.task.slug for r in failed)}", flush=True)
        exit_code = 1

    skipped = [result for result in results if result.skipped]
    if skipped:
        print(f"{len(skipped)} of {len(results)} {cadence} tasks skipped: {', '.join(r.task.slug for r in skipped)}", flush=True)
        exit_code = 1

    return exit_code
