from typing import Protocol


class ShutdownInterface(Protocol):
    """Protocol defining the shutdown state of the process running the analysis.

    This is what an analysis module is asking about when it reads
    ``self.shutdown`` or calls ``self.sleep()``: it wants to stop what it is
    doing because the process it lives in is going away.
    """

    @property
    def shutdown(self) -> bool:
        """Returns True if an immediate shutdown has been signaled.

        Long running work should abandon what it is doing.
        """
        ...

    @property
    def controlled_shutdown(self) -> bool:
        """Returns True if a controlled shutdown has been signaled.

        The current work item should still be finished; no new work is claimed.
        """
        ...
