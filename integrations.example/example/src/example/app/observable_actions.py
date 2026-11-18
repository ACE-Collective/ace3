from saq.analysis.presenter.observable_presenter import register_observable_action
from saq.constants import F_TEST
from saq.gui.observable_actions.base import ObservableAction


class ObservableActionExample(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = "example"
        self.description = "Example Observable Action"
        # a template in example_bp's template folder
        self.action_path = 'example/observable_actions/example_action.html'
        self.icon = 'ok'


register_observable_action(F_TEST, ObservableActionExample)
