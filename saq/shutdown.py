"""The single shutdown control point for an ACE process.

Every ACE process -- a service, the engine controller, a forked engine worker -- goes
through one ``ShutdownCoordinator``. It answers exactly two questions:

    is this process shutting down?      -> is_shutting_down()
    how long do I have left to do it?   -> deadline_remaining()

and it guarantees one thing:

    **the process always exits on its own before docker escalates to SIGKILL.**

That guarantee is what keeps the logs quiet. A process that is killed mid-operation
leaves held database locks, open transactions and half-written state behind, and every
peer that touches them logs an error about it. A process that exits deliberately
releases what it holds and tells the cluster it is going away.

Why a coordinator rather than another event
-------------------------------------------
Before this module ACE had roughly ten independent shutdown flags -- a
``threading.Event`` per service, two ``mp.Event`` per engine worker, three bare bools on
the engine, two state enums and a database column -- and no way to ask the general
question from library code. Code that wanted to distinguish "the database call failed"
from "the database call failed because we are shutting down" had nowhere to look, so it
logged an error either way. ``is_shutting_down()`` is that place to look.

Signal handling
---------------
Handlers do one thing: set the event. They never run ``stop()``. A signal handler runs
on the main thread, interrupting whatever it was doing, so calling ``stop()`` there
deadlocks any service whose ``stop()`` joins the threads the main thread is already
joining. Shutdown work belongs on the main path, after ``wait_for_shutdown()`` returns.

Fork safety
-----------
The flag is backed by an ``ACE_MP_CONTEXT.Event()`` created before any fork, so a forked
engine worker observes what the parent set. This mirrors what ``saq.engine.worker``
already does with its own two events.
"""

import logging
import os
import signal
import threading
import time
from typing import Callable, NamedTuple, Optional

from saq.environment import ACE_MP_CONTEXT

# how long a process gets to shut down when nobody says otherwise. this must stay
# comfortably below the smallest stop_grace_period in docker-compose.yml so that the
# escalation ladder below always runs to completion before docker's SIGKILL lands.
DEFAULT_SHUTDOWN_DEADLINE = 20.0

# how long the watchdog waits past the deadline before taking the process down itself.
# this is slack for a stop() that is nearly finished, not a second budget.
WATCHDOG_GRACE = 5.0


class ShutdownHook(NamedTuple):
    """A callback to run while shutting down, in ``order`` (ascending)."""

    order: int
    name: str
    callback: Callable[[], None]


class ShutdownCoordinator:
    """Process-wide shutdown state. One per process; see ``get_shutdown_coordinator()``.

    Args:
        deadline_seconds: how long the process may take to shut down once shutdown is
            requested. The watchdog force-exits ``WATCHDOG_GRACE`` seconds after this.
    """

    def __init__(self, deadline_seconds: float = DEFAULT_SHUTDOWN_DEADLINE):
        self.deadline_seconds = deadline_seconds

        # created pre-fork so forked children see what the parent sets
        self._event = ACE_MP_CONTEXT.Event()

        # monotonic timestamp of when shutdown was requested, or None
        self._requested_at: Optional[float] = None
        self._reason: Optional[str] = None

        self._hooks: list[ShutdownHook] = []
        self._lock = threading.RLock()
        self._watchdog: Optional[threading.Thread] = None

        # set once shutdown has finished. the watchdog waits on this rather than sleeping
        # blindly: it is a deadline for *completing* shutdown, so once shutdown is done it
        # must stand down. an armed watchdog that fires after a clean shutdown would take
        # down a process that had every right to still be running.
        self._complete = threading.Event()

        # the pid that built this coordinator. a forked child inherits the object but
        # must not run the parent's hooks or arm its own watchdog off it
        self._owner_pid = os.getpid()

    # ------------------------------------------------------------------
    # state
    # ------------------------------------------------------------------

    @property
    def is_shutting_down(self) -> bool:
        """True once shutdown has been requested, in this process or its parent."""
        return self._event.is_set()

    @property
    def reason(self) -> Optional[str]:
        return self._reason

    def deadline_remaining(self) -> float:
        """Seconds left in the shutdown budget; ``deadline_seconds`` before shutdown is
        requested, and never below zero after it."""
        if self._requested_at is None:
            return self.deadline_seconds

        return max(0.0, self.deadline_seconds - (time.monotonic() - self._requested_at))

    # ------------------------------------------------------------------
    # requesting shutdown
    # ------------------------------------------------------------------

    def request_shutdown(self, reason: str = "unspecified"):
        """Request shutdown. Idempotent -- the first reason wins and later calls are
        ignored, so a SIGTERM followed by an impatient second SIGTERM does not restart
        the clock or re-run hooks."""
        with self._lock:
            if self._event.is_set():
                logging.debug("shutdown already requested (%s), ignoring: %s", self._reason, reason)
                return

            self._reason = reason
            self._requested_at = time.monotonic()
            self._event.set()

        logging.info("shutdown requested: %s (deadline %.1fs)", reason, self.deadline_seconds)
        self._start_watchdog()

    def mark_complete(self):
        """Declare shutdown finished, standing the watchdog down.

        Call this once everything that needed stopping has stopped, immediately before
        exiting. Idempotent.
        """
        self._complete.set()

    def _signal_handler(self, signum, frame):
        """Async-signal-safe as far as we can make it in python: set a flag, nothing else.

        Note this deliberately does not call stop() -- see the module docstring."""
        try:
            name = signal.Signals(signum).name
        except ValueError:
            name = str(signum)

        self.request_shutdown(f"received {name}")

    def install_signal_handlers(self, signals=(signal.SIGTERM, signal.SIGINT)):
        """Install the shutdown signal handlers for this process.

        SIGTERM and SIGINT mean the same thing: shut down now, cleanly, within the
        deadline. Docker sends SIGTERM and an operator at a terminal sends SIGINT; there
        is no reason for them to behave differently.
        """
        for signum in signals:
            try:
                signal.signal(signum, self._signal_handler)
            except (ValueError, OSError) as e:
                # signal() only works on the main thread of the main interpreter
                logging.warning("unable to install handler for %s: %s", signum, e)

    # ------------------------------------------------------------------
    # waiting
    # ------------------------------------------------------------------

    def sleep(self, seconds: float) -> bool:
        """Sleep up to ``seconds``, waking immediately if shutdown is requested.

        Returns True if shutdown was requested. Use this instead of ``time.sleep()``
        anywhere in a loop that should not outlive a shutdown request.
        """
        if seconds <= 0:
            return self.is_shutting_down

        return self._event.wait(seconds)

    def wait_for_shutdown(self, timeout: Optional[float] = None) -> bool:
        """Block until shutdown is requested. Returns True if it was."""
        return self._event.wait(timeout)

    # ------------------------------------------------------------------
    # hooks
    # ------------------------------------------------------------------

    def register(self, name: str, callback: Callable[[], None], order: int = 100):
        """Register a callback to run during shutdown, ascending by ``order``.

        Lower numbers run first. Use low orders to stop accepting new work and high
        orders to release resources, so that nothing acquires what has just been freed.
        """
        with self._lock:
            self._hooks.append(ShutdownHook(order=order, name=name, callback=callback))

    def run_hooks(self):
        """Run every registered hook in order, bounded by the remaining deadline.

        A hook that raises or overruns does not prevent the rest from running -- the
        whole point is that shutdown completes even when part of the process is wedged.
        """
        with self._lock:
            hooks = sorted(self._hooks, key=lambda h: h.order)

        for hook in hooks:
            if self.deadline_remaining() <= 0:
                logging.warning("shutdown deadline exceeded - skipping remaining hooks from %s", hook.name)
                return

            try:
                logging.debug("running shutdown hook %s", hook.name)
                hook.callback()
            except Exception as e:
                # never let one hook's failure strand the others
                logging.warning("shutdown hook %s failed: %s", hook.name, e)

    # ------------------------------------------------------------------
    # watchdog
    # ------------------------------------------------------------------

    def _start_watchdog(self):
        """Arm the thread that force-exits the process if shutdown overruns.

        This is the backstop behind every cooperative mechanism in ACE. An analysis
        module stuck in a CPU loop, a socket read with no timeout, a thread blocked on a
        database that is already gone -- none of them can stop the process from exiting
        on time, because this thread does not depend on any of them.
        """
        if os.getpid() != self._owner_pid:
            # a forked child inherited the object; the parent owns the watchdog
            return

        with self._lock:
            if self._watchdog is not None:
                return

            self._watchdog = threading.Thread(
                target=self._watchdog_loop,
                name="shutdown-watchdog",
                daemon=True,
            )
            self._watchdog.start()

    def _watchdog_loop(self):
        deadline = self.deadline_seconds + WATCHDOG_GRACE

        if self._complete.wait(deadline):
            # shutdown finished inside its budget, which is the normal case; nothing to do
            return

        # still here, so the orderly path did not finish in time. os._exit skips
        # interpreter shutdown deliberately: at this point the remaining daemon threads
        # are blocked on peers that are already gone, and letting them unwind produces
        # exactly the error noise this whole subsystem exists to prevent
        logging.error(
            "shutdown did not complete within %.1fs (%s) - forcing exit",
            deadline, self._reason,
        )
        _flush_logging()
        os._exit(0)


def run_bounded(callback: Callable[[], None], timeout: float, name: str) -> bool:
    """Run ``callback`` on a daemon thread, waiting at most ``timeout`` seconds.

    Returns True if it finished, False if it is still running when the timeout expires.

    Shutdown paths in ACE are full of unbounded joins -- a service that joins a thread
    blocked on a dead database never returns, and the container gets SIGKILLed with the
    process still holding everything it held. Wrapping each step lets shutdown make
    progress past a wedged one instead of stopping at it. The abandoned thread is a
    daemon, so it cannot hold up interpreter exit either.
    """
    finished = threading.Event()

    def _run():
        try:
            callback()
        except Exception as e:
            logging.warning("%s failed during shutdown: %s", name, e)
        finally:
            finished.set()

    thread = threading.Thread(target=_run, name=f"bounded-{name}", daemon=True)
    thread.start()

    if finished.wait(timeout):
        return True

    logging.warning("%s did not finish within %.1fs - continuing shutdown without it", name, timeout)
    return False


def _flush_logging():
    """Best-effort flush of log handlers before a forced exit."""
    try:
        for handler in logging.getLogger().handlers:
            try:
                handler.flush()
            except Exception:
                pass
    except Exception:
        pass


# ----------------------------------------------------------------------
# process-global accessor
# ----------------------------------------------------------------------

_coordinator: Optional[ShutdownCoordinator] = None
_coordinator_lock = threading.Lock()


def get_shutdown_coordinator(deadline_seconds: Optional[float] = None) -> ShutdownCoordinator:
    """Return this process's coordinator, creating it on first use.

    ``deadline_seconds`` only applies when the coordinator is created; the process entry
    point sets it and everything else just calls this with no arguments.
    """
    global _coordinator

    with _coordinator_lock:
        if _coordinator is None:
            _coordinator = ShutdownCoordinator(
                deadline_seconds if deadline_seconds is not None else DEFAULT_SHUTDOWN_DEADLINE
            )
        elif deadline_seconds is not None and deadline_seconds != _coordinator.deadline_seconds:
            logging.debug(
                "shutdown coordinator already exists with deadline %.1fs, ignoring %.1fs",
                _coordinator.deadline_seconds, deadline_seconds,
            )

        return _coordinator


def is_shutting_down() -> bool:
    """True if this process is shutting down.

    Cheap and safe to call from anywhere, including library code that has no idea how
    the process is structured. Never creates a coordinator: a process that never built
    one is by definition not shutting down through one.
    """
    return _coordinator is not None and _coordinator.is_shutting_down


def reset_shutdown_coordinator():
    """Drop the process-global coordinator. For tests only.

    Marks it complete first. Without that, a coordinator a test asked to shut down leaves
    an armed watchdog thread behind that force-exits the whole test process some seconds
    later -- which looks exactly like the suite passing and then stopping partway through.
    """
    global _coordinator

    with _coordinator_lock:
        if _coordinator is not None:
            _coordinator.mark_complete()

        _coordinator = None
