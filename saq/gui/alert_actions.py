"""Buttons that integrations add to the alert page's toolbar.

An integration subclasses ``AlertAction`` and passes the class to ``register_alert_action()``
when its package is imported. The alert page renders one toolbar button for every registered
action that the user is permitted and that is available for the alert, then includes each
action's template once in the page body.
"""

import logging
import re
from collections.abc import Callable

_NAME = re.compile(r"[a-z0-9_]+")
# Bootstrap Icons names are lowercase words joined by dashes; anything else would add classes
_ICON = re.compile(r"[a-z0-9-]*")


class AlertAction:
    """A button on the alert toolbar.

    The button's element id is ``alert_action_<name>``. ``action_path``, when set, is a template
    included once on the alert page, with ``action`` and ``alert`` in its context. It wires the
    button up, typically a modal plus a script that posts to the integration's own route.
    """

    # lowercase letters, digits and underscores; unique across every registered action
    name: str = ""
    description: str = ""
    # a Bootstrap Icons name without the "bi-" prefix
    icon: str = ""
    action_path: str | None = None
    # disabled while the alert is locked for analysis, like the core buttons that change the tree
    modifies_analysis: bool = False
    # (major, minor) permission the user needs for the button to be shown
    permission: tuple[str, str] | None = None

    def is_available(self, alert) -> bool:
        """Whether the button applies to this alert. Runs on every render of the alert page."""
        return True


_ALERT_ACTION_REGISTRY: list[type[AlertAction]] = []


def register_alert_action(action_class: type[AlertAction]) -> None:
    """Add a button to the alert toolbar. Buttons appear in registration order."""
    if not (isinstance(action_class, type) and issubclass(action_class, AlertAction)):
        raise TypeError(f"{action_class!r} is not an AlertAction subclass")
    if not _NAME.fullmatch(action_class.name or ""):
        raise ValueError(f"alert action {action_class.__name__} needs a name of [a-z0-9_]+")
    if not action_class.description:
        raise ValueError(f"alert action {action_class.__name__} needs a description for its label")
    if not _ICON.fullmatch(action_class.icon or ""):
        raise ValueError(f"alert action {action_class.__name__} needs an icon of [a-z0-9-]+")
    if action_class in _ALERT_ACTION_REGISTRY:
        return
    if any(registered.name == action_class.name for registered in _ALERT_ACTION_REGISTRY):
        raise ValueError(f"an alert action named {action_class.name!r} is already registered")
    _ALERT_ACTION_REGISTRY.append(action_class)


def get_alert_actions(alert, has_permission: Callable[[str, str], bool]) -> list[AlertAction]:
    """The actions to show on this alert's page, for a user with these permissions.

    An action that raises while it is created or decides its availability is left out and logged:
    an integration's bug must not break the alert page.
    """
    actions = []
    for action_class in _ALERT_ACTION_REGISTRY:
        try:
            action = action_class()
            if action.permission and not has_permission(*action.permission):
                continue
            available = action.is_available(alert)
        except Exception:
            logging.warning("alert action failed to decide its availability",
                            extra={"alert_action": action_class.name}, exc_info=True)
            continue
        if available:
            actions.append(action)
    return actions
