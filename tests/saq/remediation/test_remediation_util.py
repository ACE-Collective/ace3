import pytest

from saq.constants import F_IPV4, F_TEST
from saq.database.model import Remediation, RemediationHistory, User
from saq.database.pool import get_db
from saq.environment import get_global_runtime_settings
from saq.remediation.target import (
    ObservableRemediationInterface,
    RemediationTarget,
    register_observable_remediation_interface,
)
from saq.remediation.types import RemediationAction, RemediationStatus, RemediatorStatus
from saq.remediation.util import (
    cancel_remediations,
    delete_remediations,
    get_distinct_analyst_names,
    get_distinct_remediation_actions,
    get_distinct_remediation_statuses,
    get_distinct_remediation_types,
    get_distinct_remediator_names,
    get_distinct_remediator_statuses,
    mass_remediate_targets,
    restore_remediations,
    retry_remediations,
)


@pytest.mark.integration
def test_cancel_remediations_basic():
    """test cancelling remediations without comment or user_id"""
    # create a remediation
    target = RemediationTarget("custom", F_TEST, "test_value_1")
    remediation_id = target.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
    )

    # verify initial state
    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    assert remediation.status == RemediationStatus.NEW.value

    # update status to IN_PROGRESS so we can cancel it
    remediation.status = RemediationStatus.IN_PROGRESS.value
    get_db().commit()

    # cancel the remediation
    count = cancel_remediations([remediation_id])
    assert count == 1

    # verify the remediation was cancelled
    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    assert remediation.status == RemediatorStatus.CANCELLED.remediation_status.value
    assert remediation.result == RemediatorStatus.CANCELLED.value

    # verify history was created
    history = (
        get_db()
        .query(RemediationHistory)
        .filter(RemediationHistory.remediation_id == remediation_id)
        .first()
    )
    assert history is not None
    assert history.result == RemediatorStatus.CANCELLED.value
    assert history.status == RemediatorStatus.CANCELLED.remediation_status.value
    assert "cancelled by unknown user" in history.message


@pytest.mark.integration
def test_cancel_remediations_with_comment():
    """test cancelling remediations with a custom comment"""
    target = RemediationTarget("custom", F_TEST, "test_value_2")
    remediation_id = target.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
    )

    # update status to IN_PROGRESS
    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    remediation.status = RemediationStatus.IN_PROGRESS.value
    get_db().commit()

    # cancel with custom comment
    custom_comment = "testing custom cancellation"
    count = cancel_remediations([remediation_id], comment=custom_comment)
    assert count == 1

    # verify history has custom comment
    history = (
        get_db()
        .query(RemediationHistory)
        .filter(RemediationHistory.remediation_id == remediation_id)
        .first()
    )
    assert history.message == custom_comment


@pytest.mark.integration
def test_cancel_remediations_with_user_id():
    """test cancelling remediations with a user_id"""
    target = RemediationTarget("custom", F_TEST, "test_value_3")
    remediation_id = target.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
    )

    # update status to IN_PROGRESS
    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    remediation.status = RemediationStatus.IN_PROGRESS.value
    get_db().commit()

    # get the automation user
    user = (
        get_db()
        .query(User)
        .filter(User.id == get_global_runtime_settings().automation_user_id)
        .first()
    )
    assert user is not None

    # cancel with user_id
    count = cancel_remediations([remediation_id], user_id=user.id)
    assert count == 1

    # verify history includes user display name
    history = (
        get_db()
        .query(RemediationHistory)
        .filter(RemediationHistory.remediation_id == remediation_id)
        .first()
    )
    assert f"cancelled by {user.display_name}" in history.message


@pytest.mark.integration
def test_cancel_remediations_multiple():
    """test cancelling multiple remediations at once"""
    # create multiple remediations
    target1 = RemediationTarget("custom", F_TEST, "test_value_4")
    remediation_id1 = target1.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
    )

    target2 = RemediationTarget("custom", F_TEST, "test_value_5")
    remediation_id2 = target2.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
    )

    # update both to IN_PROGRESS
    for rid in [remediation_id1, remediation_id2]:
        remediation = get_db().query(Remediation).filter(Remediation.id == rid).first()
        remediation.status = RemediationStatus.IN_PROGRESS.value
    get_db().commit()

    # cancel both
    count = cancel_remediations([remediation_id1, remediation_id2])
    assert count == 2

    # verify both were cancelled
    for rid in [remediation_id1, remediation_id2]:
        remediation = get_db().query(Remediation).filter(Remediation.id == rid).first()
        assert remediation.status == RemediatorStatus.CANCELLED.remediation_status.value
        assert remediation.result == RemediatorStatus.CANCELLED.value


@pytest.mark.integration
def test_cancel_remediations_only_in_progress():
    """test that only IN_PROGRESS remediations are cancelled"""
    # create a remediation that is NEW
    target1 = RemediationTarget("custom", F_TEST, "test_value_6")
    remediation_id1 = target1.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
    )

    # create a remediation that is IN_PROGRESS
    target2 = RemediationTarget("custom", F_TEST, "test_value_7")
    remediation_id2 = target2.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
    )
    remediation2 = get_db().query(Remediation).filter(Remediation.id == remediation_id2).first()
    remediation2.status = RemediationStatus.IN_PROGRESS.value
    get_db().commit()

    # try to cancel both
    count = cancel_remediations([remediation_id1, remediation_id2])
    assert count == 2

    # verify only the IN_PROGRESS one was actually updated
    remediation1 = get_db().query(Remediation).filter(Remediation.id == remediation_id1).first()
    assert remediation1.status == RemediationStatus.NEW.value  # unchanged

    remediation2 = get_db().query(Remediation).filter(Remediation.id == remediation_id2).first()
    assert remediation2.status == RemediatorStatus.CANCELLED.remediation_status.value


@pytest.mark.integration
def test_retry_remediations():
    """test retrying completed remediations"""
    # create a remediation and mark it as completed
    target = RemediationTarget("custom", F_TEST, "test_value_8")
    remediation_id = target.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
    )

    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    remediation.status = RemediationStatus.COMPLETED.value
    remediation.result = RemediatorStatus.SUCCESS.value
    remediation.lock = "test_lock"
    get_db().commit()

    # retry the remediation
    count = retry_remediations([remediation_id])
    assert count == 1

    # verify the remediation was reset to NEW
    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    assert remediation.status == RemediationStatus.NEW.value
    assert remediation.result is None
    assert remediation.update_time is None
    assert remediation.lock is None
    assert remediation.lock_time is None


@pytest.mark.integration
def test_retry_remediations_multiple():
    """test retrying multiple completed remediations"""
    # create multiple completed remediations
    target1 = RemediationTarget("custom", F_TEST, "test_value_9")
    remediation_id1 = target1.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
    )

    target2 = RemediationTarget("custom", F_TEST, "test_value_10")
    remediation_id2 = target2.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
    )

    # mark both as completed
    for rid in [remediation_id1, remediation_id2]:
        remediation = get_db().query(Remediation).filter(Remediation.id == rid).first()
        remediation.status = RemediationStatus.COMPLETED.value
        remediation.result = RemediatorStatus.SUCCESS.value
    get_db().commit()

    # retry both
    count = retry_remediations([remediation_id1, remediation_id2])
    assert count == 2

    # verify both were reset
    for rid in [remediation_id1, remediation_id2]:
        remediation = get_db().query(Remediation).filter(Remediation.id == rid).first()
        assert remediation.status == RemediationStatus.NEW.value
        assert remediation.result is None


@pytest.mark.integration
def test_retry_remediations_only_completed():
    """test that only COMPLETED remediations are retried"""
    # create a NEW remediation
    target1 = RemediationTarget("custom", F_TEST, "test_value_11")
    remediation_id1 = target1.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
    )

    # create a COMPLETED remediation
    target2 = RemediationTarget("custom", F_TEST, "test_value_12")
    remediation_id2 = target2.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
    )
    remediation2 = get_db().query(Remediation).filter(Remediation.id == remediation_id2).first()
    remediation2.status = RemediationStatus.COMPLETED.value
    remediation2.result = RemediatorStatus.SUCCESS.value
    get_db().commit()

    # try to retry both
    count = retry_remediations([remediation_id1, remediation_id2])
    assert count == 2

    # verify only the COMPLETED one was actually reset
    remediation1 = get_db().query(Remediation).filter(Remediation.id == remediation_id1).first()
    assert remediation1.status == RemediationStatus.NEW.value  # unchanged

    remediation2 = get_db().query(Remediation).filter(Remediation.id == remediation_id2).first()
    assert remediation2.status == RemediationStatus.NEW.value  # reset


@pytest.mark.integration
def test_restore_remediations():
    """test restoring completed REMOVE remediations"""
    # create a completed REMOVE remediation
    target = RemediationTarget("custom", F_TEST, "test_value_13")
    remediation_id = target.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id, "restore_key_1"
    )

    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    remediation.status = RemediationStatus.COMPLETED.value
    remediation.result = RemediatorStatus.SUCCESS.value
    get_db().commit()

    # count existing remediations
    initial_count = get_db().query(Remediation).count()

    # restore the remediation
    count = restore_remediations([remediation_id])
    assert count == 1

    # verify a new RESTORE remediation was created
    final_count = get_db().query(Remediation).count()
    assert final_count == initial_count + 1

    # find the new RESTORE remediation
    restore_remediation = (
        get_db()
        .query(Remediation)
        .filter(
            Remediation.action == RemediationAction.RESTORE.value,
            Remediation.type == F_TEST,
            Remediation.key == "test_value_13",
        )
        .first()
    )
    assert restore_remediation is not None
    assert restore_remediation.restore_key == "restore_key_1"


@pytest.mark.integration
def test_restore_remediations_filters():
    """test that only completed REMOVE remediations with SUCCESS result are restored"""
    # create a REMOVE remediation that is NEW
    target1 = RemediationTarget("custom", F_TEST, "test_value_14")
    remediation_id1 = target1.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
    )

    # create a REMOVE remediation that is COMPLETED but FAILED
    target2 = RemediationTarget("custom", F_TEST, "test_value_15")
    remediation_id2 = target2.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
    )
    remediation2 = get_db().query(Remediation).filter(Remediation.id == remediation_id2).first()
    remediation2.status = RemediationStatus.COMPLETED.value
    remediation2.result = RemediatorStatus.FAILED.value
    get_db().commit()

    # create a RESTORE remediation
    target3 = RemediationTarget("custom", F_TEST, "test_value_16")
    remediation_id3 = target3.queue_remediation(
        RemediationAction.RESTORE, get_global_runtime_settings().automation_user_id
    )
    remediation3 = get_db().query(Remediation).filter(Remediation.id == remediation_id3).first()
    remediation3.status = RemediationStatus.COMPLETED.value
    remediation3.result = RemediatorStatus.SUCCESS.value
    get_db().commit()

    initial_count = get_db().query(Remediation).count()

    # try to restore all three
    count = restore_remediations([remediation_id1, remediation_id2, remediation_id3])
    assert count == 0  # none should be restored

    # verify no new remediations were created
    final_count = get_db().query(Remediation).count()
    assert final_count == initial_count


@pytest.mark.integration
def test_restore_remediations_multiple():
    """test restoring multiple remediations"""
    # create multiple completed REMOVE remediations
    target1 = RemediationTarget("custom", F_TEST, "test_value_17")
    remediation_id1 = target1.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id, "restore_key_2"
    )

    target2 = RemediationTarget("custom", F_TEST, "test_value_18")
    remediation_id2 = target2.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id, "restore_key_3"
    )

    # mark both as completed with success
    for rid in [remediation_id1, remediation_id2]:
        remediation = get_db().query(Remediation).filter(Remediation.id == rid).first()
        remediation.status = RemediationStatus.COMPLETED.value
        remediation.result = RemediatorStatus.SUCCESS.value
    get_db().commit()

    initial_count = get_db().query(Remediation).count()

    # restore both
    count = restore_remediations([remediation_id1, remediation_id2])
    assert count == 2

    # verify two new RESTORE remediations were created
    final_count = get_db().query(Remediation).count()
    assert final_count == initial_count + 2


@pytest.mark.integration
def test_delete_remediations():
    """test deleting remediations"""
    # create a remediation
    target = RemediationTarget("custom", F_TEST, "test_value_19")
    remediation_id = target.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
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
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
    )

    target2 = RemediationTarget("custom", F_TEST, "test_value_21")
    remediation_id2 = target2.queue_remediation(
        RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id
    )

    # delete both
    count = delete_remediations([remediation_id1, remediation_id2])
    assert count == 2

    # verify both are gone
    for rid in [remediation_id1, remediation_id2]:
        remediation = get_db().query(Remediation).filter(Remediation.id == rid).first()
        assert remediation is None


@pytest.mark.integration
def test_mass_remediate_targets():
    """test mass remediation of targets"""

    class _test_interface(ObservableRemediationInterface):
        def get_remediation_targets(self, observable) -> list[RemediationTarget]:
            # return two targets for each observable
            return [
                RemediationTarget("remediator1", observable.type, observable.value),
                RemediationTarget("remediator2", observable.type, observable.value),
            ]

    # register the interface
    register_observable_remediation_interface(F_IPV4, _test_interface())

    initial_count = get_db().query(Remediation).count()

    # mass remediate two IP addresses
    observable_values = ["192.168.1.1", "10.0.0.1"]
    count = mass_remediate_targets(
        F_IPV4, observable_values, get_global_runtime_settings().automation_user_id
    )

    # should create 4 remediations (2 targets per observable * 2 observables)
    assert count == 4

    final_count = get_db().query(Remediation).count()
    assert final_count == initial_count + 4

    # verify remediations were created with correct values
    remediations = get_db().query(Remediation).filter(Remediation.type == F_IPV4).all()
    assert len(remediations) == 4

    # check that we have remediations for both IPs and both remediators
    ip_values = {r.key for r in remediations}
    assert "192.168.1.1" in ip_values
    assert "10.0.0.1" in ip_values

    remediator_names = {r.name for r in remediations}
    assert "remediator1" in remediator_names
    assert "remediator2" in remediator_names


@pytest.mark.integration
def test_mass_remediate_targets_invalid_observable():
    """test that invalid observables are skipped in mass remediation"""

    class _test_interface(ObservableRemediationInterface):
        def get_remediation_targets(self, observable) -> list[RemediationTarget]:
            return [RemediationTarget("remediator1", observable.type, observable.value)]

    register_observable_remediation_interface(F_IPV4, _test_interface())

    initial_count = get_db().query(Remediation).count()

    # mix valid and invalid IP addresses
    observable_values = ["192.168.1.1", "not_an_ip", "10.0.0.1"]
    count = mass_remediate_targets(
        F_IPV4, observable_values, get_global_runtime_settings().automation_user_id
    )

    # should create 2 remediations (1 target per valid observable * 2 valid observables)
    assert count == 2

    final_count = get_db().query(Remediation).count()
    assert final_count == initial_count + 2


@pytest.mark.integration
def test_get_distinct_remediator_names():
    """test getting distinct remediator names"""
    # initially should be empty
    names = get_distinct_remediator_names()
    assert names == []

    # create remediations with different remediator names
    target1 = RemediationTarget("remediator_a", F_TEST, "test_value_22")
    target1.queue_remediation(RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id)

    target2 = RemediationTarget("remediator_b", F_TEST, "test_value_23")
    target2.queue_remediation(RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id)

    target3 = RemediationTarget("remediator_a", F_TEST, "test_value_24")
    target3.queue_remediation(RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id)

    # get distinct names
    names = get_distinct_remediator_names()
    assert len(names) == 2
    assert "remediator_a" in names
    assert "remediator_b" in names


@pytest.mark.integration
def test_get_distinct_remediation_types():
    """test getting distinct remediation types"""
    # initially should be empty
    types = get_distinct_remediation_types()
    assert types == []

    # create remediations with different types
    target1 = RemediationTarget("custom", F_TEST, "test_value_25")
    target1.queue_remediation(RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id)

    target2 = RemediationTarget("custom", F_IPV4, "192.168.1.2")
    target2.queue_remediation(RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id)

    target3 = RemediationTarget("custom", F_TEST, "test_value_26")
    target3.queue_remediation(RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id)

    # get distinct types
    types = get_distinct_remediation_types()
    assert len(types) == 2
    assert F_TEST in types
    assert F_IPV4 in types


@pytest.mark.unit
def test_get_distinct_remediation_actions():
    """test getting distinct remediation actions"""
    actions = get_distinct_remediation_actions()
    assert len(actions) == 2
    assert RemediationAction.REMOVE.value in actions
    assert RemediationAction.RESTORE.value in actions


@pytest.mark.unit
def test_get_distinct_remediator_statuses():
    """test getting distinct remediator statuses"""
    statuses = get_distinct_remediator_statuses()
    assert len(statuses) == 6
    assert RemediatorStatus.DELAYED.value in statuses
    assert RemediatorStatus.ERROR.value in statuses
    assert RemediatorStatus.FAILED.value in statuses
    assert RemediatorStatus.IGNORE.value in statuses
    assert RemediatorStatus.SUCCESS.value in statuses
    assert RemediatorStatus.CANCELLED.value in statuses


@pytest.mark.unit
def test_get_distinct_remediation_statuses():
    """test getting distinct remediation statuses"""
    statuses = get_distinct_remediation_statuses()
    assert len(statuses) == 3
    assert RemediationStatus.NEW.value in statuses
    assert RemediationStatus.IN_PROGRESS.value in statuses
    assert RemediationStatus.COMPLETED.value in statuses


@pytest.mark.integration
def test_get_distinct_analyst_names():
    """test getting distinct analyst names from remediations"""
    # create a remediation with the automation user
    target = RemediationTarget("custom", F_TEST, "test_value_27")
    target.queue_remediation(RemediationAction.REMOVE, get_global_runtime_settings().automation_user_id)

    # get analyst names
    names = get_distinct_analyst_names()
    assert len(names) >= 1

    # verify the automation user's display name is in the list
    user = (
        get_db()
        .query(User)
        .filter(User.id == get_global_runtime_settings().automation_user_id)
        .first()
    )
    assert user.display_name in names
