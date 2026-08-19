from typing import Protocol

from saq.remediation.external.types import CheckWorkItem


class CheckListener(Protocol):
    """Receives check work items from the collector — exactly one listener per
    registered probe name. Mirrors :class:`FileCollectionListener`."""

    def handle_external_check_request(self, work_item: CheckWorkItem):
        ...

    def get_backoff_delays(self) -> tuple[int, int]:
        """The (initial, max) retry delay seconds for this probe's rows. The
        collector falls back to its own defaults when a listener (e.g. a test
        double) doesn't implement this."""
        ...
