import pytest

from saq.alert_routing import reset_alert_routers


@pytest.fixture(autouse=True)
def _fresh_alert_routers():
    """Each test starts from the configured routers and leaves nothing registered behind."""
    reset_alert_routers()
    yield
    reset_alert_routers()
