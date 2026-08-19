"""Shared fixtures for external remediation check tests."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from saq.database.model import Alert, ExternalRemediationCheck
from saq.database.pool import get_db
from saq.remediation.external.probe import ExternalRemediationProbe
from saq.remediation.external.types import ProbeOutcome, ProbeTarget
from saq.util.uuid import storage_dir_from_uuid


class FakeProbeConfig:
    """Minimal stand-in for :class:`ExternalRemediationProbeConfig` — avoids
    pulling Pydantic into every worker/collector test."""

    def __init__(
        self,
        name="fake_probe",
        observable_type="email_delivery",
        thread_count=1,
        initial_delay_seconds=1,
        max_delay_seconds=60,
        max_retries=3,
        deadline_seconds=3600,
        supersede_grace_seconds=1800,
    ):
        self.name = name
        self.observable_type = observable_type
        self.thread_count = thread_count
        self.initial_delay_seconds = initial_delay_seconds
        self.max_delay_seconds = max_delay_seconds
        self.max_retries = max_retries
        self.deadline_seconds = deadline_seconds
        self.supersede_grace_seconds = supersede_grace_seconds
        self.enabled = True
        self.python_module = "tests.saq.remediation.external.conftest"
        self.python_class = "FakeProbe"


class FakeProbe(ExternalRemediationProbe):
    """A probe whose return value is set per-test."""

    def __init__(self, config=None, outcome_factory=None):
        super().__init__(config or FakeProbeConfig())
        self.calls: list[ProbeTarget] = []
        self.outcome_factory = outcome_factory or (
            lambda target: ProbeOutcome(pending=True, message="not yet")
        )

    def probe(self, target: ProbeTarget) -> ProbeOutcome:
        self.calls.append(target)
        return self.outcome_factory(target)


@pytest.fixture
def db_alert():
    """Minimal Alert row so the disposition sweep test has something to join."""
    alert_uuid = str(uuid.uuid4())
    alert = Alert(
        uuid=alert_uuid,
        storage_dir=storage_dir_from_uuid(alert_uuid),
        location="unittest",
        tool="test_tool",
        tool_instance="test_instance",
        alert_type="test",
        description="alert for external remediation check tests",
    )
    get_db().add(alert)
    get_db().commit()
    return alert


@pytest.fixture
def make_check(db_alert):
    """Factory that inserts an ExternalRemediationCheck row with sensible
    defaults — tests override only the field they're exercising."""
    created: list[int] = []

    def _make(
        probe_name="fake_probe",
        observable_type="email_delivery",
        observable_value=None,
        alert_uuid=None,
        status="NEW",
        result=None,
        events_json=None,
        context_json=None,
        retry_count=0,
        max_retries=3,
        deadline=None,
        update_time=None,
        lock=None,
        lock_time=None,
    ):
        check = ExternalRemediationCheck(
            probe_name=probe_name,
            observable_type=observable_type,
            observable_value=observable_value or f"<msg-{uuid.uuid4()}>|alice@example.com",
            alert_uuid=alert_uuid or db_alert.uuid,
            status=status,
            result=result,
            events_json=events_json,
            context_json=context_json,
            retry_count=retry_count,
            max_retries=max_retries,
            deadline=deadline or (datetime.now(timezone.utc) + timedelta(hours=1)),
            update_time=update_time,
            lock=lock,
            lock_time=lock_time,
        )
        get_db().add(check)
        get_db().commit()
        created.append(check.id)
        return check

    yield _make

    # Cleanup happens implicitly via the test-db transaction rollback.
