from typing import TYPE_CHECKING

from saq.engine.shutdown_interface import ShutdownInterface

if TYPE_CHECKING:
    from saq.engine.worker import Worker


class WorkerShutdownAdapter(ShutdownInterface):
    """Adapter that implements ShutdownInterface using a Worker instance.

    The Worker owns the two multiprocessing events the shutdown signal actually
    lives in. They are created before the fork, so a worker process reads what
    the manager set in the parent.
    """

    def __init__(self, worker: "Worker"):
        """Initialize the adapter with a worker instance.

        Args:
            worker: The worker instance whose shutdown state is being reported
        """
        self.worker = worker

    @property
    def shutdown(self) -> bool:
        """Returns True if the worker has been told to shut down immediately."""
        return self.worker.is_immediate_shutdown()

    @property
    def controlled_shutdown(self) -> bool:
        """Returns True if the worker has been told to shut down when complete."""
        return self.worker.is_controlled_shutdown()
