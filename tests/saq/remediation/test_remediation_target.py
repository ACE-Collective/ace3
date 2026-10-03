import pytest

from saq.constants import F_TEST
from saq.database.model import Observable, ObservableRemediationMapping, Remediation
from saq.database.pool import get_db
from saq.configuration.config import get_config
from saq.remediation.target import DefaultObservableRemediationInterface, ObservableRemediationInterface, RemediationTarget, get_observable_remediation_interfaces, register_observable_remediation_interface
from saq.remediation.types import RemediationAction, RemediationStatus

@pytest.mark.integration
def test_queue_remediation():
    assert get_db().query(Remediation).count() == 0
    assert get_db().query(Observable).count() == 0
    target = RemediationTarget("custom", F_TEST, "test")
    remediation_id = target.queue_remediation(RemediationAction.REMOVE, get_config().global_settings.automation_user_id)
    remediation = get_db().query(Remediation).filter(Remediation.id == remediation_id).first()
    assert remediation
    assert remediation.name == "custom"
    assert remediation.type == F_TEST
    assert remediation.key == "test"
    assert remediation.action == RemediationAction.REMOVE.value
    assert remediation.user_id == get_config().global_settings.automation_user_id
    assert remediation.result is None
    assert remediation.restore_key is None
    assert remediation.comment is None
    assert remediation.status == RemediationStatus.NEW.value

    observable = get_db().query(Observable).first()
    assert observable
    assert observable.type == F_TEST
    assert observable.value == b"test"

    or_mapping = get_db().query(ObservableRemediationMapping).filter(ObservableRemediationMapping.observable_id == observable.id, ObservableRemediationMapping.remediation_id == remediation.id).first()
    assert or_mapping
    assert or_mapping.observable_id == observable.id
    assert or_mapping.remediation_id == remediation.id

@pytest.mark.unit
def test_register_observable_remediation_interface():
    class _custom_remediation_interface(ObservableRemediationInterface):
        def get_remediation_targets(self, observable: Observable) -> list[RemediationTarget]:
            return []

    # we get a default interface if one isn't specified for a given observable type
    interfaces = get_observable_remediation_interfaces(F_TEST)
    assert len(interfaces) == 1
    assert isinstance(interfaces[0], DefaultObservableRemediationInterface)
    register_observable_remediation_interface(F_TEST, _custom_remediation_interface())
    interfaces = get_observable_remediation_interfaces(F_TEST)
    assert len(interfaces) == 1
    assert isinstance(interfaces[0], _custom_remediation_interface)

@pytest.mark.unit
def test_get_observable_remediation_targets_default():
    """Test that get_observable_remediation_targets returns empty list for unregistered observable types."""
    from saq.observables.generator import create_observable
    from saq.remediation.target import get_observable_remediation_targets

    observable = create_observable(F_TEST, "test_value")
    targets = get_observable_remediation_targets(observable)

    assert isinstance(targets, list)
    assert len(targets) == 0

@pytest.mark.unit
def test_get_observable_remediation_targets_single_interface():
    """Test get_observable_remediation_targets with a single registered interface."""
    from saq.observables.generator import create_observable
    from saq.remediation.target import get_observable_remediation_targets

    class _custom_interface(ObservableRemediationInterface):
        def get_remediation_targets(self, observable: Observable) -> list[RemediationTarget]:
            return [
                RemediationTarget("remediator1", observable.type, observable.value),
                RemediationTarget("remediator2", observable.type, observable.value)
            ]

    register_observable_remediation_interface(F_TEST, _custom_interface())
    observable = create_observable(F_TEST, "test_value")
    targets = get_observable_remediation_targets(observable)

    assert len(targets) == 2
    assert all(isinstance(t, RemediationTarget) for t in targets)
    assert targets[0].remediator_name == "remediator1"
    assert targets[0].observable_type == F_TEST
    assert targets[0].observable_value == "test_value"
    assert targets[1].remediator_name == "remediator2"

@pytest.mark.unit
def test_get_observable_remediation_targets_multiple_interfaces():
    """Test get_observable_remediation_targets with multiple registered interfaces."""
    from saq.constants import F_IP
    from saq.observables.generator import create_observable
    from saq.remediation.target import get_observable_remediation_targets

    class _interface_one(ObservableRemediationInterface):
        def get_remediation_targets(self, observable: Observable) -> list[RemediationTarget]:
            return [RemediationTarget("remediator1", observable.type, observable.value)]

    class _interface_two(ObservableRemediationInterface):
        def get_remediation_targets(self, observable: Observable) -> list[RemediationTarget]:
            return [RemediationTarget("remediator2", observable.type, observable.value)]

    class _interface_three(ObservableRemediationInterface):
        def get_remediation_targets(self, observable: Observable) -> list[RemediationTarget]:
            return [
                RemediationTarget("remediator3", observable.type, observable.value),
                RemediationTarget("remediator4", observable.type, observable.value)
            ]

    register_observable_remediation_interface(F_IP, _interface_one())
    register_observable_remediation_interface(F_IP, _interface_two())
    register_observable_remediation_interface(F_IP, _interface_three())

    observable = create_observable(F_IP, "192.168.1.1")
    targets = get_observable_remediation_targets(observable)

    assert len(targets) == 4
    assert all(isinstance(t, RemediationTarget) for t in targets)
    remediator_names = [t.remediator_name for t in targets]
    assert "remediator1" in remediator_names
    assert "remediator2" in remediator_names
    assert "remediator3" in remediator_names
    assert "remediator4" in remediator_names

@pytest.mark.unit
def test_get_observable_remediation_targets_empty_interface():
    """Test get_observable_remediation_targets when interface returns empty list."""
    from saq.observables.generator import create_observable
    from saq.remediation.target import get_observable_remediation_targets

    class _empty_interface(ObservableRemediationInterface):
        def get_remediation_targets(self, observable: Observable) -> list[RemediationTarget]:
            return []

    register_observable_remediation_interface(F_TEST, _empty_interface())
    observable = create_observable(F_TEST, "test_value")
    targets = get_observable_remediation_targets(observable)

    assert isinstance(targets, list)
    assert len(targets) == 0

@pytest.mark.unit
def test_get_observable_remediation_targets_different_observable_values():
    """Test that observable values are correctly passed to remediation targets."""
    from saq.observables.generator import create_observable
    from saq.remediation.target import get_observable_remediation_targets

    class _value_capturing_interface(ObservableRemediationInterface):
        def get_remediation_targets(self, observable: Observable) -> list[RemediationTarget]:
            return [RemediationTarget("remediator", observable.type, f"modified_{observable.value}")]

    register_observable_remediation_interface(F_TEST, _value_capturing_interface())
    observable = create_observable(F_TEST, "original_value")
    targets = get_observable_remediation_targets(observable)

    assert len(targets) == 1
    assert targets[0].observable_value == "modified_original_value"

@pytest.mark.unit
def test_register_observable_remediation_interface_prevents_duplicate_types():
    """Test that registering the same interface type twice is prevented."""
    from saq.constants import F_URL
    from saq.observables.generator import create_observable
    from saq.remediation.target import get_observable_remediation_targets, get_observable_remediation_interfaces

    class _duplicate_interface(ObservableRemediationInterface):
        def get_remediation_targets(self, observable: Observable) -> list[RemediationTarget]:
            return [RemediationTarget("remediator", observable.type, observable.value)]

    # Register the same type twice
    register_observable_remediation_interface(F_URL, _duplicate_interface())
    register_observable_remediation_interface(F_URL, _duplicate_interface())

    # Should only have one interface registered
    interfaces = get_observable_remediation_interfaces(F_URL)
    assert len(interfaces) == 1

    # Should only get one target
    observable = create_observable(F_URL, "http://example.com")
    targets = get_observable_remediation_targets(observable)
    assert len(targets) == 1
