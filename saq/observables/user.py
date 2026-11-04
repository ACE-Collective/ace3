from saq.analysis.presenter.observable_presenter import ObservablePresenter, register_observable_presenter
from saq.constants import F_USER
from saq.observables.base import CaselessObservable


class UserObservable(CaselessObservable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_USER, *args, **kwargs)

    @CaselessObservable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

        # Drop the domain/host portion of the username if it's there. Take the
        # segment after the *last* backslash so multi-segment (host\DOMAIN\user)
        # and double-backslash (DOMAIN\\user) separators still resolve to the
        # bare account name instead of an empty inter-backslash segment.
        if '\\' in self._value:
            self._value = self._value.split('\\')[-1]

    @property
    def jinja_template_path(self):
        return "analysis/user_observable.html"

    @property
    def jinja_available_actions(self):
        result = []
        result.extend(super().jinja_available_actions)
        return result


class UserObservablePresenter(ObservablePresenter):
    """Presenter for UserObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/user_observable.html"


register_observable_presenter(UserObservable, UserObservablePresenter)
