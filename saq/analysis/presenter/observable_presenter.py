import logging
from typing import TYPE_CHECKING, Type

from saq import Observable
from saq.database.database_observable import observable_is_set_for_detection

from saq.environment import get_global_runtime_settings
from saq.gui import ObservableAction

# Registry for custom observable presenter classes
_OBSERVABLE_PRESENTER_REGISTRY: dict[Type[Observable], Type["ObservablePresenter"]] = {}


def register_observable_presenter(
    observable_class: Type[Observable], presenter_class: Type["ObservablePresenter"]
):
    assert issubclass(observable_class, Observable)
    assert issubclass(presenter_class, ObservablePresenter)

    """Register a custom presenter for a specific observable class."""
    _OBSERVABLE_PRESENTER_REGISTRY[observable_class] = presenter_class


def create_observable_presenter(observable):
    """Factory function to create an appropriate presenter for an Observable object."""
    observable_class = type(observable)
    presenter_class = _OBSERVABLE_PRESENTER_REGISTRY.get(
        observable_class, ObservablePresenter
    )
    return presenter_class(observable)


# registry for custom observable actions
_OBSERVABLE_ACTION_REGISTRY: dict[str, list[Type["ObservableAction"]]] = {}


def register_observable_action(
    observable_type: str, action_class: Type["ObservableAction"]
):
    """Register a custom action for a specific observable type."""
    assert isinstance(observable_type, str)
    assert issubclass(action_class, ObservableAction)
    if observable_type not in _OBSERVABLE_ACTION_REGISTRY:
        _OBSERVABLE_ACTION_REGISTRY[observable_type] = []

    _OBSERVABLE_ACTION_REGISTRY[observable_type].append(action_class)


class ObservablePresenter:
    """Handles presentation logic for Observable objects, separating UI concerns from domain logic."""

    def __init__(self, observable):
        """Initialize presenter with an Observable instance."""
        from saq.analysis.observable import Observable

        assert isinstance(observable, Observable)
        self._observable = observable

    @property
    def template_path(self) -> str:
        """Returns the template path to use when rendering this observable."""
        return "analysis/default_observable.html"

    @property
    def available_actions(self) -> list:
        """Returns a list of ObservableAction objects for this observable."""
        from saq.gui import (
            ObservableActionUnWhitelist,
            ObservableActionWhitelist,
            ObservableActionAddTag,
            ObservableActionSeparator,
            ObservableActionEnableDetection,
            ObservableActionDisableableDetection,
            ObservableActionAdjustExpiration,
        )
        if self._observable.type in get_global_runtime_settings().gui_whitelist_excluded_observable_types:
            actions = [ObservableActionAddTag()]
        else:
            actions = [
                ObservableActionAddTag(),
                ObservableActionSeparator(),
                ObservableActionWhitelist(),
                ObservableActionUnWhitelist(),
            ]

        if observable_is_set_for_detection(self._observable):
            actions.extend(
                [
                    ObservableActionSeparator(),
                    ObservableActionDisableableDetection(),
                    ObservableActionAdjustExpiration(),
                ]
            )
        else:
            actions.extend(
                [ObservableActionSeparator(), ObservableActionEnableDetection()]
            )

        # add any custom actions for this observable type
        if self._observable.type in _OBSERVABLE_ACTION_REGISTRY:
            actions.append(ObservableActionSeparator())
            for action_class in _OBSERVABLE_ACTION_REGISTRY[self._observable.type]:
                actions.append(action_class())

        return actions

    # XXX why do we need this?
    # Delegate access to the underlying observable object for any other properties needed
    def __getattr__(self, name):
        """Delegate any missing attributes to the underlying observable object."""
        return getattr(self._observable, name)


# The specialized presenters for specific observable types are now co-located
# with their respective observable classes in the observables modules