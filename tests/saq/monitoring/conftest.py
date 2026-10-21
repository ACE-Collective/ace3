import pytest

from saq.monitoring.threaded_monitor import ACEThreadedMonitor


class ConcreteTestMonitor(ACEThreadedMonitor):
    """A concrete subclass of ACEThreadedMonitor for testing the abstract base class."""

    def __init__(self, name="test_monitor", frequency=0.1, execute_side_effect=None):
        super().__init__(name=name, frequency=frequency)
        self.execute_count = 0
        self.execute_side_effect = execute_side_effect

    def execute(self):
        self.execute_count += 1
        if self.execute_side_effect:
            raise self.execute_side_effect


@pytest.fixture
def concrete_monitor():
    return ConcreteTestMonitor()

