import pytest

from saq.alert_routing import RouteStage, route_alert
from tests.saq.helpers import create_root_analysis

# core's autouse fixture: each test starts from the routers configured in etc/saq.integration.yaml,
# none a test registered. A conftest fixture reaches only its own directory, so it is imported here
from tests.saq.alert_routing.conftest import _fresh_alert_routers  # noqa: F401

pytestmark = pytest.mark.unit


def test_a_tagged_alert_goes_to_the_example_queue():
    root = create_root_analysis()
    root.add_tag("example_route")

    decision = route_alert(root, RouteStage.PRE_INSERT, final=False)

    assert (decision.router, decision.queue) == ("example_tag_router", "example")


def test_an_untagged_alert_is_left_to_the_other_routers():
    assert route_alert(create_root_analysis(), RouteStage.PRE_INSERT, final=False) is None


def test_an_existing_alert_is_never_rerouted():
    root = create_root_analysis()
    root.add_tag("example_route")

    assert route_alert(root, RouteStage.POST_ANALYSIS, final=True) is None
