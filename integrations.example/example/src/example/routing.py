"""An example alert router.

Registered as `example_tag_router` by the `alert_routers` entry in etc/saq.integration.yaml. It
sends a new alert carrying one tag to one queue, and does nothing to any other alert, so
installing the example integration changes nothing until something adds that tag.

See "Routing alerts" in docs/INTEGRATIONS.md.
"""

from typing import Optional

from saq.alert_routing import AlertRouter, RouteDecision, RouteStage


class ExampleTagRouter(AlertRouter):
    """Routes alerts tagged `tag` to `queue` when they are created.

    A router only reads the tree and returns a decision. It never changes the tree, and it
    should not raise; see the AlertRouter contract.
    """

    def __init__(self, name: str, priority: int, tag: str, queue: str):
        super().__init__(name=name, priority=priority)
        self.tag = tag
        self.queue = queue

    def route(self, root, stage: RouteStage) -> Optional[RouteDecision]:
        if stage != RouteStage.PRE_INSERT:
            return None

        if not root.has_tag(self.tag):
            return None

        return RouteDecision(queue=self.queue, reason=f"tagged {self.tag}")
