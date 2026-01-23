"""Fixtures for file_collection tests."""
import uuid

import pytest

from saq.database.model import Alert
from saq.database.pool import get_db
from saq.util.uuid import storage_dir_from_uuid


@pytest.fixture
def db_alert():
    """Creates a minimal Alert record in the database for testing."""
    alert_uuid = str(uuid.uuid4())
    alert = Alert(
        uuid=alert_uuid,
        storage_dir=storage_dir_from_uuid(alert_uuid),
        location="unittest",
        tool="test_tool",
        tool_instance="test_instance",
        alert_type="test",
        description="Test alert for file collection",
    )
    get_db().add(alert)
    get_db().commit()
    return alert
