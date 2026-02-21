from unittest.mock import MagicMock, patch

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


@pytest.fixture
def mock_db_cursor():
    """Patches get_db_connection and returns a mock cursor.

    The monitors use `with get_db_connection() as db:` then `db.cursor()`,
    then iterate the cursor. This fixture wires up __enter__/__exit__ and
    cursor() properly.

    Usage: apply via @patch on the specific module's get_db_connection.
    Returns a tuple of (mock_db, mock_cursor) for further configuration.
    """
    mock_cursor = MagicMock()
    mock_cursor.__iter__ = MagicMock(return_value=iter([]))

    mock_db = MagicMock()
    mock_db.cursor.return_value = mock_cursor
    mock_db.__enter__ = MagicMock(return_value=mock_db)
    mock_db.__exit__ = MagicMock(return_value=False)

    return mock_db, mock_cursor
