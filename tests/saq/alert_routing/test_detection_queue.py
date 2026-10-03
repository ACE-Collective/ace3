"""The built-in detection queue router: a detection's `queue` meta (e.g. a yara rule's) routes
the new alert, but only when every detection point requests a queue."""

import pytest

from saq.alert_routing import RouteStage
from saq.alert_routing.detection_queue import DetectionQueueRouter
from saq.constants import QUEUE_DEFAULT
from tests.saq.helpers import create_root_analysis

pytestmark = pytest.mark.unit


def _route(root, stage=RouteStage.PRE_INSERT):
    return DetectionQueueRouter().route(root, stage)


def test_single_routed_detection_sets_queue():
    root = create_root_analysis()
    assert root.queue == QUEUE_DEFAULT
    root.add_detection_point("yara hit", queue="experimental")

    decision = _route(root)
    assert decision.queue == "experimental"
    # a router never changes the tree; the registry's caller applies the decision
    assert root.queue == QUEUE_DEFAULT


def test_routed_plus_plain_detection_keeps_default():
    """A co-occurring normal detection means it's a real alert -> stay in the default queue."""
    root = create_root_analysis()
    root.add_detection_point("yara hit", queue="experimental")
    root.add_detection_point("real detection")  # no queue

    assert _route(root) is None


def test_explicit_queue_not_clobbered():
    root = create_root_analysis(queue="incoming")
    root.add_detection_point("yara hit", queue="experimental")

    assert _route(root) is None


def test_no_detections_leaves_default():
    assert _route(create_root_analysis()) is None


def test_conflicting_queues_pick_sorted_first():
    root = create_root_analysis()
    root.add_detection_point("hit b", queue="bravo")
    root.add_detection_point("hit a", queue="alpha")

    assert _route(root).queue == "alpha"


def test_routed_detection_on_observable():
    """Detections attached to observables (the real yara path) are also resolved."""
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec("yara_rule", "routed_rule")
    observable.add_detection_point("yara hit", queue="experimental")

    assert _route(root).queue == "experimental"


def test_root_detections_are_counted_once():
    """all_detection_points already includes the root's own detection points (FR-24); a plain
    one there keeps the default queue."""
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec("yara_rule", "routed_rule")
    observable.add_detection_point("yara hit", queue="experimental")
    root.add_detection_point("plain root detection")

    assert _route(root) is None


def test_only_when_the_alert_is_created():
    root = create_root_analysis()
    root.add_detection_point("yara hit", queue="experimental")

    assert _route(root, RouteStage.POST_ANALYSIS) is None
