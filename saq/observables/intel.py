from saq.analysis.observable import Observable
from saq.analysis.presenter.observable_presenter import ObservablePresenter, register_observable_presenter
from saq.constants import F_INDICATOR


class IndicatorObservable(Observable):
    def __init__(self, *args, **kwargs):
        super().__init__(F_INDICATOR, *args, **kwargs)

    @Observable.value.setter
    def value(self, new_value):
        self._value = new_value.strip()

    @property
    def jinja_template_path(self):
        return "analysis/indicator_observable.html"

    @property
    def jinja_available_actions(self):
        result = []
        return result


class IndicatorObservablePresenter(ObservablePresenter):
    """Presenter for IndicatorObservable."""

    @property
    def template_path(self) -> str:
        return "analysis/indicator_observable.html"


register_observable_presenter(IndicatorObservable, IndicatorObservablePresenter)
