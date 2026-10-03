"""The alert router interface: what a router is given, and what it may decide."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    # annotation only: saq.analysis.root imports far more than a router module needs
    from saq.analysis.root import RootAnalysis

# alerts.queue
QUEUE_MAX_LENGTH = 64


class RouteStage(str, Enum):
    # inside ALERT(), before the alerts row is created: the decision becomes the row's queue
    PRE_INSERT = "pre_insert"
    # in the engine, after an analysis pass over an existing alert: the decision moves the alert
    # through move_alert_to_queue(), and only while it is OPEN and nobody has taken it
    POST_ANALYSIS = "post_analysis"


@dataclass(frozen=True)
class RouteDecision:
    """Send the alert to `queue`. `router` is filled in by the registry with the deciding
    router's name, whatever the router put there."""

    queue: str
    reason: str
    router: Optional[str] = None

    def __post_init__(self):
        if not isinstance(self.queue, str) or not self.queue.strip():
            raise ValueError(f"a route decision needs a queue, got {self.queue!r}")
        if len(self.queue) > QUEUE_MAX_LENGTH:
            raise ValueError(f"queue {self.queue!r} is longer than {QUEUE_MAX_LENGTH} characters")


class AlertRouter(ABC):
    """Decides which queue an alert belongs in (docs/INTEGRATIONS.md, "Routing alerts").

    Routers run in ascending `priority`; the first one that returns a decision wins. One router
    object serves every thread of its process, so route() must be thread-safe.

    The contract:
    - route() never changes the tree. The tree belongs to the caller, and the routed queue is
      the only change made on a router's behalf; tags and detections belong in analysis modules.
      A router may write rows of its own in the caller's transaction (keyed on the alert uuid:
      at PRE_INSERT the alerts row has no id yet).
    - route() should not raise. If it does, the exception is reported, the router is skipped
      and the next one runs: a router never breaks an alert insert or an analysis pass.
    """

    def __init__(self, name: str, priority: int, **kwargs):
        if kwargs:
            raise TypeError(f"router {name!r} got unexpected arguments: {', '.join(sorted(kwargs))}")
        self.name = name
        self.priority = priority

    @abstractmethod
    def route(self, root: "RootAnalysis", stage: RouteStage) -> Optional[RouteDecision]:
        """Return a decision to send the alert to a queue, or None to let the next router decide."""
        raise NotImplementedError()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r}, priority={self.priority})"
