import pytest

from saq.constants import F_TEST, F_IP, F_FQDN
from saq.database.model import Remediation, RemediationHistory
from saq.database.pool import get_db
from saq.configuration.config import get_config
from saq.remediation.database import get_remediation_history
from saq.remediation.target import RemediationTarget
from saq.remediation.types import RemediationAction, RemediationStatus, RemediatorStatus


@pytest.mark.integration
def test_get_remediation_history_empty():
    """Test get_remediation_history returns empty list when no history exists."""
    target = RemediationTarget("email_remediator", F_TEST, "test_value")
    history = get_remediation_history(target)

    assert isinstance(history, list)
    assert len(history) == 0


@pytest.mark.integration
def test_get_remediation_history_single_entry():
    """Test get_remediation_history returns a single history entry."""
    target = RemediationTarget("email_remediator", F_IP, "192.168.1.1")

    # Create a remediation
    remediation = Remediation(
        name=target.remediator_name,
        type=target.observable_type,
        key=target.observable_value,
        action=RemediationAction.REMOVE.value,
        user_id=get_config().global_settings.automation_user_id,
        status=RemediationStatus.IN_PROGRESS.value
    )
    get_db().add(remediation)
    get_db().flush()

    # Create a history entry
    history_entry = RemediationHistory(
        remediation_id=remediation.id,
        result=RemediatorStatus.SUCCESS.value,
        message="Email successfully removed from mailbox",
        status=RemediationStatus.COMPLETED.value
    )
    get_db().add(history_entry)
    get_db().commit()

    # Retrieve history
    history = get_remediation_history(target)

    assert len(history) == 1
    assert history[0].id == history_entry.id
    assert history[0].remediation_id == remediation.id
    assert history[0].result == RemediatorStatus.SUCCESS.value
    assert history[0].message == "Email successfully removed from mailbox"
    assert history[0].status == RemediationStatus.COMPLETED.value


@pytest.mark.integration
def test_get_remediation_history_multiple_entries():
    """Test get_remediation_history returns multiple history entries."""
    target = RemediationTarget("firewall_remediator", F_IP, "10.0.0.5")

    # Create a remediation
    remediation = Remediation(
        name=target.remediator_name,
        type=target.observable_type,
        key=target.observable_value,
        action=RemediationAction.REMOVE.value,
        user_id=get_config().global_settings.automation_user_id,
        status=RemediationStatus.COMPLETED.value
    )
    get_db().add(remediation)
    get_db().flush()

    # Create multiple history entries
    history_entry_1 = RemediationHistory(
        remediation_id=remediation.id,
        result=RemediatorStatus.DELAYED.value,
        message="Starting remediation",
        status=RemediationStatus.IN_PROGRESS.value
    )
    history_entry_2 = RemediationHistory(
        remediation_id=remediation.id,
        result=RemediatorStatus.SUCCESS.value,
        message="IP blocked on firewall",
        status=RemediationStatus.COMPLETED.value
    )
    history_entry_3 = RemediationHistory(
        remediation_id=remediation.id,
        result=RemediatorStatus.SUCCESS.value,
        message="Verification complete",
        status=RemediationStatus.COMPLETED.value
    )

    get_db().add_all([history_entry_1, history_entry_2, history_entry_3])
    get_db().commit()

    # Retrieve history
    history = get_remediation_history(target)

    assert len(history) == 3
    # Verify all entries are present
    history_ids = [h.id for h in history]
    assert history_entry_1.id in history_ids
    assert history_entry_2.id in history_ids
    assert history_entry_3.id in history_ids


@pytest.mark.integration
def test_get_remediation_history_multiple_remediations_same_target():
    """Test get_remediation_history returns history from all remediations matching the target."""
    target = RemediationTarget("email_remediator", F_TEST, "test@example.com")

    # Create first remediation (remove)
    remediation_1 = Remediation(
        name=target.remediator_name,
        type=target.observable_type,
        key=target.observable_value,
        action=RemediationAction.REMOVE.value,
        user_id=get_config().global_settings.automation_user_id,
        status=RemediationStatus.COMPLETED.value
    )
    get_db().add(remediation_1)
    get_db().flush()

    # Create second remediation (restore)
    remediation_2 = Remediation(
        name=target.remediator_name,
        type=target.observable_type,
        key=target.observable_value,
        action=RemediationAction.RESTORE.value,
        user_id=get_config().global_settings.automation_user_id,
        status=RemediationStatus.COMPLETED.value
    )
    get_db().add(remediation_2)
    get_db().flush()

    # Create history for first remediation
    history_rem1 = RemediationHistory(
        remediation_id=remediation_1.id,
        result=RemediatorStatus.SUCCESS.value,
        message="Email removed",
        status=RemediationStatus.COMPLETED.value
    )

    # Create history for second remediation
    history_rem2 = RemediationHistory(
        remediation_id=remediation_2.id,
        result=RemediatorStatus.SUCCESS.value,
        message="Email restored",
        status=RemediationStatus.COMPLETED.value
    )

    get_db().add_all([history_rem1, history_rem2])
    get_db().commit()

    # Retrieve history
    history = get_remediation_history(target)

    assert len(history) == 2
    # Both remediation histories should be present
    messages = [h.message for h in history]
    assert "Email removed" in messages
    assert "Email restored" in messages


@pytest.mark.integration
def test_get_remediation_history_filter_by_remediator_name():
    """Test get_remediation_history filters correctly by remediator_name."""
    # Create remediation with remediator_name "email_remediator"
    remediation_1 = Remediation(
        name="email_remediator",
        type=F_TEST,
        key="test_value",
        action=RemediationAction.REMOVE.value,
        user_id=get_config().global_settings.automation_user_id,
        status=RemediationStatus.COMPLETED.value
    )
    get_db().add(remediation_1)
    get_db().flush()

    # Create remediation with different remediator_name but same type and key
    remediation_2 = Remediation(
        name="firewall_remediator",
        type=F_TEST,
        key="test_value",
        action=RemediationAction.REMOVE.value,
        user_id=get_config().global_settings.automation_user_id,
        status=RemediationStatus.COMPLETED.value
    )
    get_db().add(remediation_2)
    get_db().flush()

    # Create history for both
    history_1 = RemediationHistory(
        remediation_id=remediation_1.id,
        result=RemediatorStatus.SUCCESS.value,
        message="Email remediation",
        status=RemediationStatus.COMPLETED.value
    )
    history_2 = RemediationHistory(
        remediation_id=remediation_2.id,
        result=RemediatorStatus.SUCCESS.value,
        message="Firewall remediation",
        status=RemediationStatus.COMPLETED.value
    )
    get_db().add_all([history_1, history_2])
    get_db().commit()

    # Query for email_remediator only
    target = RemediationTarget("email_remediator", F_TEST, "test_value")
    history = get_remediation_history(target)

    assert len(history) == 1
    assert history[0].message == "Email remediation"


@pytest.mark.integration
def test_get_remediation_history_filter_by_observable_type():
    """Test get_remediation_history filters correctly by observable_type."""
    # Create remediation with observable_type F_IP
    remediation_1 = Remediation(
        name="test_remediator",
        type=F_IP,
        key="192.168.1.1",
        action=RemediationAction.REMOVE.value,
        user_id=get_config().global_settings.automation_user_id,
        status=RemediationStatus.COMPLETED.value
    )
    get_db().add(remediation_1)
    get_db().flush()

    # Create remediation with different observable_type but same name and key
    remediation_2 = Remediation(
        name="test_remediator",
        type=F_FQDN,
        key="192.168.1.1",  # Same value but different type
        action=RemediationAction.REMOVE.value,
        user_id=get_config().global_settings.automation_user_id,
        status=RemediationStatus.COMPLETED.value
    )
    get_db().add(remediation_2)
    get_db().flush()

    # Create history for both
    history_1 = RemediationHistory(
        remediation_id=remediation_1.id,
        result=RemediatorStatus.SUCCESS.value,
        message="IPv4 remediation",
        status=RemediationStatus.COMPLETED.value
    )
    history_2 = RemediationHistory(
        remediation_id=remediation_2.id,
        result=RemediatorStatus.SUCCESS.value,
        message="FQDN remediation",
        status=RemediationStatus.COMPLETED.value
    )
    get_db().add_all([history_1, history_2])
    get_db().commit()

    # Query for F_IP only
    target = RemediationTarget("test_remediator", F_IP, "192.168.1.1")
    history = get_remediation_history(target)

    assert len(history) == 1
    assert history[0].message == "IPv4 remediation"


@pytest.mark.integration
def test_get_remediation_history_filter_by_observable_value():
    """Test get_remediation_history filters correctly by observable_value."""
    # Create remediation with observable_value "value1"
    remediation_1 = Remediation(
        name="test_remediator",
        type=F_TEST,
        key="value1",
        action=RemediationAction.REMOVE.value,
        user_id=get_config().global_settings.automation_user_id,
        status=RemediationStatus.COMPLETED.value
    )
    get_db().add(remediation_1)
    get_db().flush()

    # Create remediation with different observable_value but same name and type
    remediation_2 = Remediation(
        name="test_remediator",
        type=F_TEST,
        key="value2",
        action=RemediationAction.REMOVE.value,
        user_id=get_config().global_settings.automation_user_id,
        status=RemediationStatus.COMPLETED.value
    )
    get_db().add(remediation_2)
    get_db().flush()

    # Create history for both
    history_1 = RemediationHistory(
        remediation_id=remediation_1.id,
        result=RemediatorStatus.SUCCESS.value,
        message="Remediation for value1",
        status=RemediationStatus.COMPLETED.value
    )
    history_2 = RemediationHistory(
        remediation_id=remediation_2.id,
        result=RemediatorStatus.SUCCESS.value,
        message="Remediation for value2",
        status=RemediationStatus.COMPLETED.value
    )
    get_db().add_all([history_1, history_2])
    get_db().commit()

    # Query for value1 only
    target = RemediationTarget("test_remediator", F_TEST, "value1")
    history = get_remediation_history(target)

    assert len(history) == 1
    assert history[0].message == "Remediation for value1"


@pytest.mark.integration
def test_get_remediation_history_no_match():
    """Test get_remediation_history returns empty list when target doesn't match any remediation."""
    # Create a remediation
    remediation = Remediation(
        name="email_remediator",
        type=F_TEST,
        key="existing_value",
        action=RemediationAction.REMOVE.value,
        user_id=get_config().global_settings.automation_user_id,
        status=RemediationStatus.COMPLETED.value
    )
    get_db().add(remediation)
    get_db().flush()

    # Create history
    history_entry = RemediationHistory(
        remediation_id=remediation.id,
        result=RemediatorStatus.SUCCESS.value,
        message="Test message",
        status=RemediationStatus.COMPLETED.value
    )
    get_db().add(history_entry)
    get_db().commit()

    # Query for non-matching target
    target = RemediationTarget("email_remediator", F_TEST, "non_existing_value")
    history = get_remediation_history(target)

    assert len(history) == 0


@pytest.mark.integration
def test_get_remediation_history_remediation_without_history():
    """Test get_remediation_history returns empty list when remediation exists but has no history."""
    target = RemediationTarget("test_remediator", F_TEST, "test_value")

    # Create a remediation without any history entries
    remediation = Remediation(
        name=target.remediator_name,
        type=target.observable_type,
        key=target.observable_value,
        action=RemediationAction.REMOVE.value,
        user_id=get_config().global_settings.automation_user_id,
        status=RemediationStatus.NEW.value
    )
    get_db().add(remediation)
    get_db().commit()

    # Retrieve history
    history = get_remediation_history(target)

    assert len(history) == 0


@pytest.mark.integration
def test_get_remediation_history_complex_scenario():
    """Test get_remediation_history with a complex scenario involving multiple remediations and history entries."""
    target = RemediationTarget("email_remediator", F_TEST, "complex@example.com")

    # Create multiple remediations for the same target
    remediations = []
    for i in range(3):
        remediation = Remediation(
            name=target.remediator_name,
            type=target.observable_type,
            key=target.observable_value,
            action=RemediationAction.REMOVE.value if i % 2 == 0 else RemediationAction.RESTORE.value,
            user_id=get_config().global_settings.automation_user_id,
            status=RemediationStatus.COMPLETED.value
        )
        get_db().add(remediation)
        get_db().flush()
        remediations.append(remediation)

    # Create multiple history entries for each remediation
    total_history_count = 0
    for remediation in remediations:
        for j in range(2):
            history_entry = RemediationHistory(
                remediation_id=remediation.id,
                result=RemediatorStatus.SUCCESS.value if j == 1 else RemediatorStatus.DELAYED.value,
                message=f"Remediation {remediation.id} step {j}",
                status=RemediationStatus.COMPLETED.value if j == 1 else RemediationStatus.IN_PROGRESS.value
            )
            get_db().add(history_entry)
            total_history_count += 1

    get_db().commit()

    # Retrieve history
    history = get_remediation_history(target)

    # Should have all history entries from all matching remediations
    assert len(history) == total_history_count
    assert len(history) == 6  # 3 remediations * 2 history entries each
