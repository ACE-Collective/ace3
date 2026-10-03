"""The built-in router for detection queue meta (a yara rule's `queue` meta, for example)."""

import logging
from typing import Optional

from saq.alert_routing.router import AlertRouter, RouteDecision, RouteStage
from saq.constants import QUEUE_DEFAULT

DETECTION_QUEUE_ROUTER_NAME = "detection_queue"
DETECTION_QUEUE_ROUTER_PRIORITY = 500


class DetectionQueueRouter(AlertRouter):
    """Routes a new alert to the queue its detection points request, but only when EVERY
    detection point requests one. If any plain (non-routed) detection exists the alert is
    "real" and stays where it is so analysts see it. A queue that is not the default (set by a
    submission or a hunt) is never overridden."""

    def __init__(self, name: str = DETECTION_QUEUE_ROUTER_NAME, priority: int = DETECTION_QUEUE_ROUTER_PRIORITY):
        super().__init__(name=name, priority=priority)

    def route(self, root, stage: RouteStage) -> Optional[RouteDecision]:
        # only when the alert is created, when the full set of pre-alert detections is known
        if stage != RouteStage.PRE_INSERT:
            return None

        if root.queue != QUEUE_DEFAULT:
            return None

        # all_detection_points includes the root's own detection points (modules such as tag.py
        # add detections on the root)
        detection_points = list(root.all_detection_points)
        if not detection_points:
            return None

        queues = {getattr(dp, "queue", None) for dp in detection_points}
        if None in queues:
            # at least one normal detection -> keep the default queue
            return None

        requested = sorted(q for q in queues if q)
        if not requested:
            return None

        chosen = requested[0]
        if len(requested) > 1:
            logging.warning(f"{root} has multiple detection queues requested {requested}; routing to {chosen}")

        return RouteDecision(queue=chosen, reason="every detection point requests this queue")
