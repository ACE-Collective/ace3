from typing import Optional, Type

from saq import Observable
from aceapi_v2.observables.service import observable_is_interesting
from aceapi_v2.sync import run_async_with_session
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


def create_observable_presenter(observable, **kwargs):
    """Factory function to create an appropriate presenter for an Observable object.

    Any keyword arguments are passed through to the presenter constructor -- see
    ObservablePresenter.__init__ for the batched lookups the alert view supplies.
    """
    # walk the MRO so subclasses (e.g. EmailFirstHopIPObservable -> IPObservable)
    # inherit their parent's registered presenter instead of falling back to the default
    for observable_class in type(observable).__mro__:
        presenter_class = _OBSERVABLE_PRESENTER_REGISTRY.get(observable_class)
        if presenter_class is not None:
            return presenter_class(observable, **kwargs)

    return ObservablePresenter(observable, **kwargs)


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

    def __init__(self, observable, detection_status: Optional[bool] = None, is_interesting: Optional[bool] = None):
        """Initialize presenter with an Observable instance.

        detection_status and is_interesting are the two per-observable database
        answers the action menu needs. The alert view already looks both of them
        up in bulk for the whole tree (get_all_observable_detections /
        get_interesting_observables_by_hashes), so it passes them in here rather
        than have every presenter re-query. Left as None -- any caller outside
        that view -- the presenter falls back to querying for itself.
        """
        from saq.analysis.observable import Observable

        assert isinstance(observable, Observable)
        self._observable = observable
        self._detection_status = detection_status
        self._is_interesting = is_interesting
        self._available_actions = None

    @property
    def template_path(self) -> str:
        """Returns the template path to use when rendering this observable."""
        return "analysis/default_observable.html"

    @property
    def is_set_for_detection(self) -> bool:
        """Returns True if this observable is enabled for future detection."""
        if self._detection_status is None:
            self._detection_status = observable_is_set_for_detection(self._observable)

        return self._detection_status

    @property
    def is_interesting(self) -> bool:
        """Returns True if this observable is marked interesting."""
        if self._is_interesting is None:
            self._is_interesting = run_async_with_session(
                observable_is_interesting, self._observable.type, self._observable.sha256_bytes)

        return self._is_interesting

    @property
    def available_actions(self) -> list:
        """Returns a list of ObservableAction objects for this observable.

        Cached on the presenter: default_observable.html reads this three times
        per observable node (menu emptiness check, menu items, action templates)
        and the tree can carry hundreds of nodes.
        """
        if self._available_actions is None:
            self._available_actions = self._build_available_actions()

        return self._available_actions

    def _build_available_actions(self) -> list:
        """Builds the action list. Subclasses extend this rather than
        available_actions so that the caching above still applies."""
        from saq.gui import (
            ObservableActionAddComment,
            ObservableActionUnWhitelist,
            ObservableActionWhitelist,
            ObservableActionSeparator,
            ObservableActionEnableDetection,
            ObservableActionDisableableDetection,
            ObservableActionAdjustExpiration,
            ObservableActionMarkInteresting,
            ObservableActionUnmarkInteresting,
        )
        if self._observable.type in get_global_runtime_settings().gui_whitelist_excluded_observable_types:
            actions = []
        else:
            actions = [
                ObservableActionWhitelist(),
                ObservableActionUnWhitelist(),
            ]

        if self.is_set_for_detection:
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

        # add interesting toggle
        if self.is_interesting:
            actions.extend([ObservableActionSeparator(), ObservableActionUnmarkInteresting()])
        else:
            actions.extend([ObservableActionSeparator(), ObservableActionMarkInteresting()])

        actions.extend([ObservableActionSeparator(), ObservableActionAddComment()])

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