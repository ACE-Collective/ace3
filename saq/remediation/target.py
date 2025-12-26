
import logging
from typing import Optional, Protocol, runtime_checkable
from saq.analysis.observable import Observable
from saq.database.model import Remediation
from saq.database.util.alert import get_alert_by_uuid
from saq.remediation.remediator import Remediator, get_remediator_by_name
from saq.remediation.types import RemediationAction

# NOTE
# a RemediationTarget represents a potential target
# a Remediation (from the database) represents an actual remediation that has been performed

class RemediationTarget:
    def __init__(self, remediator_name: str, observable_type: str, observable_value: str):
        assert isinstance(remediator_name, str)
        assert isinstance(observable_type, str)
        assert isinstance(observable_value, str)

        # the type defines the kind of remediation that needs to take place (for example, "email")
        # this controls which Remediator gets selected to handle this target
        # this corresponds to the name column in the remediation table
        self.remediator_name = remediator_name

        # the type of the observable that is being remediated
        # this corresponds to the type column in the remediation table
        self.observable_type = observable_type

        # the value can be any value (string) and the interpretation is left up to the Remediator
        # this corresponds to the key column in the remediation table
        self.observable_value = observable_value

    def __eq__(self, other):
        """Equality comparison based on all three attributes."""
        if not isinstance(other, RemediationTarget):
            return NotImplemented

        return (self.remediator_name == other.remediator_name and
                self.observable_type == other.observable_type and
                self.observable_value == other.observable_value)

    def __hash__(self):
        """Hash based on all three attributes to make the class hashable."""
        return hash((self.remediator_name, self.observable_type, self.observable_value))

    @property
    def remediator(self) -> Remediator:
        return get_remediator_by_name(self.remediator_name)

    #
    # Database operations
    # ------------------------------------------------------------

    def get_current_remediation(self) -> Optional[Remediation]:
        from saq.remediation.database import get_current_remediation
        return get_current_remediation(self)

    # insert a remediation entry into the database which is then processed by the remediation service
    def queue_remediation(self, action: RemediationAction, user_id: int, restore_key: Optional[str]=None) -> int:
        from saq.remediation.database import queue_remediation
        return queue_remediation(self, action, user_id, restore_key)

    def cancel_current_remediation(self) -> bool:
        from saq.remediation.database import cancel_current_remediation
        return cancel_current_remediation(self)

    def delete_current_remediation(self) -> bool:
        from saq.remediation.database import delete_current_remediation
        return delete_current_remediation(self)

@runtime_checkable
class ObservableRemediationInterface(Protocol):
    """Interface for objects that can generate remediation targets for an observable."""
    def get_remediation_targets(self, observable: Observable) -> list[RemediationTarget]:
        """Returns a list of remediation targets for the given observable."""
        ...

class DefaultObservableRemediationInterface(ObservableRemediationInterface):
    """Default implementation of the observable remediation interface."""
    def get_remediation_targets(self, observable: Observable) -> list[RemediationTarget]:
        """By default we return an empty list of remediation targets."""
        return []

OBSERVABLE_REMEDIATION_INTERFACE_REGISTRY: dict[str, list[ObservableRemediationInterface]] = {}

def reset_observable_remediation_interface_registry():
    """Resets the observable remediation interface registry."""
    OBSERVABLE_REMEDIATION_INTERFACE_REGISTRY.clear()

def get_observable_remediation_interface_registry() -> dict[str, ObservableRemediationInterface]:
    """Returns the observable remediation interface registry."""
    return OBSERVABLE_REMEDIATION_INTERFACE_REGISTRY

def register_observable_remediation_interface(observable_type: str, interface: ObservableRemediationInterface):
    """Registers a remediation interface for a specific observable type."""
    assert isinstance(observable_type, str)
    assert isinstance(interface, ObservableRemediationInterface)
    if observable_type not in get_observable_remediation_interface_registry():
        get_observable_remediation_interface_registry()[observable_type] = []

    for existing_interface in get_observable_remediation_interface_registry()[observable_type]:
        if isinstance(existing_interface, type(interface)):
            logging.warning(f"remediation interface {interface} already registered for observable type {observable_type}")
            return

    get_observable_remediation_interface_registry()[observable_type].append(interface)

def get_observable_remediation_interfaces(observable_type: str) -> list[ObservableRemediationInterface]:
    """Returns the remediation interface for a specific observable type."""
    assert isinstance(observable_type, str)
    return get_observable_remediation_interface_registry().get(observable_type, [DefaultObservableRemediationInterface()])

def get_observable_remediation_targets(observable: Observable) -> list[RemediationTarget]:
    """Returns a list of remediation targets for the given observable."""
    assert isinstance(observable, Observable)
    targets: list[RemediationTarget] = []
    for interface in get_observable_remediation_interfaces(observable.type):
        targets.extend(interface.get_remediation_targets(observable))

    return targets

def get_remediation_targets_by_alert_uuids(alert_uuids: list[str]) -> list[RemediationTarget]:
    """Returns a list of remediation targets for the given alert uuids."""
    targets: list[RemediationTarget] = []
    for alert_uuid in alert_uuids:
        alert = get_alert_by_uuid(alert_uuid)
        if alert is None:
            logging.warning(f"alert {alert_uuid} not found in remediation target list")
            continue

        alert.root_analysis.load()
        for observable in alert.root_analysis.all_observables:
            targets.extend(get_observable_remediation_targets(observable))

    targets = list(set(targets))
    return sorted(targets, key=lambda x: f"{x.remediator_name}|{x.observable_type}|{x.observable_value}")
