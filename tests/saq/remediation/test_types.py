import pytest

from saq.remediation.types import RemediationStatus, RemediatorStatus


@pytest.mark.unit
def test_not_found_is_complete_but_not_a_failure():
    assert RemediatorStatus.NOT_FOUND.completed
    assert not RemediatorStatus.NOT_FOUND.failure
    assert not RemediatorStatus.NOT_FOUND.in_progress
    assert RemediatorStatus.NOT_FOUND.remediation_status is RemediationStatus.COMPLETED


@pytest.mark.unit
def test_failure_statuses():
    assert {s for s in RemediatorStatus if s.failure} == {RemediatorStatus.FAILED, RemediatorStatus.ERROR}
    assert {s for s in RemediatorStatus if s.in_progress} == {RemediatorStatus.DELAYED}
