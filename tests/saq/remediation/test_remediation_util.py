import pytest

from saq.constants import F_TEST
from saq.database.model import Remediation, RemediationHistory, User
from saq.database.pool import get_db
from saq.configuration.config import get_config
from saq.database.util.user_management import add_user
from saq.remediation.target import RemediationTarget
from saq.remediation.types import RemediationAction, RemediationStatus, RemediatorStatus
from saq.remediation.util import (
    cancel_remediation,
    delete_remediations,
    restore_remediation,
    retry_remediation,
)


@pytest.mark.integration
def test_delete_remediations():
    """test deleting remediations"""
    # create a remediation
    target = RemediationTarget("custom", F_TEST, "test_value_19")
    remediation_id = target.queue_remediation(
        RemediationAction.REMOVE, get_config().global_settings.automation_user_id
    )

    # verify it exists
    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    assert remediation is not None

    # delete it
    count = delete_remediations([remediation_id])
    assert count == 1

    # verify it's gone
    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    assert remediation is None


@pytest.mark.integration
def test_delete_remediations_multiple():
    """test deleting multiple remediations"""
    # create multiple remediations
    target1 = RemediationTarget("custom", F_TEST, "test_value_20")
    remediation_id1 = target1.queue_remediation(
        RemediationAction.REMOVE, get_config().global_settings.automation_user_id
    )

    target2 = RemediationTarget("custom", F_TEST, "test_value_21")
    remediation_id2 = target2.queue_remediation(
        RemediationAction.REMOVE, get_config().global_settings.automation_user_id
    )

    # delete both
    count = delete_remediations([remediation_id1, remediation_id2])
    assert count == 2

    # verify both are gone
    for rid in [remediation_id1, remediation_id2]:
        remediation = get_db().query(Remediation).filter(Remediation.id == rid).first()
        assert remediation is None


def _remediation_in(status: RemediationStatus, value: str, result: RemediatorStatus | None = None,
                    action: RemediationAction = RemediationAction.REMOVE, restore_key: str | None = None) -> int:
    target = RemediationTarget("custom", F_TEST, value)
    remediation_id = target.queue_remediation(action, get_config().global_settings.automation_user_id, restore_key)
    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    remediation.status = status.value
    remediation.result = result.value if result else None
    get_db().commit()
    return remediation_id


@pytest.mark.integration
@pytest.mark.parametrize("status", [RemediationStatus.NEW, RemediationStatus.IN_PROGRESS])
def test_cancel_remediation_stops_one_that_has_not_completed(status):
    """A queued remediation is stopped as well as a running one."""
    remediation_id = _remediation_in(status, f"cancel_one_{status.value}")
    user_id = get_config().global_settings.automation_user_id

    assert cancel_remediation(remediation_id, user_id) is True

    get_db().expire_all()
    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    assert (remediation.status, remediation.result) == (RemediationStatus.COMPLETED.value, RemediatorStatus.CANCELLED.value)
    (history,) = get_db().query(RemediationHistory).filter(RemediationHistory.remediation_id == remediation_id).all()
    user = get_db().query(User).filter(User.id == user_id).first()
    assert history.message == f"cancelled by {user.display_name}"


@pytest.mark.integration
def test_cancel_remediation_leaves_a_completed_one_alone():
    remediation_id = _remediation_in(RemediationStatus.COMPLETED, "cancel_one_completed", RemediatorStatus.SUCCESS)

    assert cancel_remediation(remediation_id) is False

    get_db().expire_all()
    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    assert remediation.result == RemediatorStatus.SUCCESS.value
    assert get_db().query(RemediationHistory).filter(RemediationHistory.remediation_id == remediation_id).count() == 0


@pytest.mark.integration
def test_cancel_remediation_unknown_id():
    assert cancel_remediation(999999) is False


@pytest.mark.integration
def test_retry_remediation_queues_a_completed_one_again():
    remediation_id = _remediation_in(RemediationStatus.COMPLETED, "retry_completed", RemediatorStatus.FAILED)

    assert retry_remediation(remediation_id) is True

    get_db().expire_all()
    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    assert (remediation.status, remediation.result, remediation.lock) == (RemediationStatus.NEW.value, None, None)


@pytest.mark.integration
@pytest.mark.parametrize("status", [RemediationStatus.NEW, RemediationStatus.IN_PROGRESS])
def test_retry_remediation_leaves_one_that_has_not_completed_alone(status):
    remediation_id = _remediation_in(status, f"retry_{status.value}", RemediatorStatus.DELAYED)

    assert retry_remediation(remediation_id) is False

    get_db().expire_all()
    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    assert (remediation.status, remediation.result) == (status.value, RemediatorStatus.DELAYED.value)


@pytest.mark.integration
def test_retry_remediation_unknown_id():
    assert retry_remediation(999999) is False


@pytest.mark.integration
def test_restore_remediation_uses_the_removals_own_restore_key():
    removal = _remediation_in(RemediationStatus.COMPLETED, "restore_me", RemediatorStatus.SUCCESS,
                              restore_key="removal-key")
    _remediation_in(RemediationStatus.COMPLETED, "restore_me", RemediatorStatus.SUCCESS, restore_key="later-key")
    # the restore is the analyst's who asks for it, not the remover's (the automation user)
    analyst = add_user(username="restorer", email="restorer@localhost", display_name="restorer", password="TestPass123!")

    restore_id = restore_remediation(removal, analyst.id)

    restore = get_db().query(Remediation).filter(Remediation.id == restore_id).one()
    assert (restore.action, restore.status, restore.key) == (RemediationAction.RESTORE.value, RemediationStatus.NEW.value, "restore_me")
    assert (restore.restore_key, restore.user_id) == ("removal-key", analyst.id)


@pytest.mark.integration
@pytest.mark.parametrize("action, status, result", [
    (RemediationAction.REMOVE, RemediationStatus.COMPLETED, RemediatorStatus.FAILED),
    (RemediationAction.REMOVE, RemediationStatus.NEW, None),
    (RemediationAction.RESTORE, RemediationStatus.COMPLETED, RemediatorStatus.SUCCESS),
])
def test_restore_remediation_needs_a_removal_that_succeeded(action, status, result):
    remediation_id = _remediation_in(status, "not_restorable", result, action=action)

    assert restore_remediation(remediation_id, get_config().global_settings.automation_user_id) is None
    assert get_db().query(Remediation).count() == 1
