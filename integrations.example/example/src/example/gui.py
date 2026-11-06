# Only the GUI imports this module, when it builds its app (gui_module in etc/saq.integration.yaml), so
# it can import Flask and the blueprint at module level.
from flask import Flask

import example.app.views  # noqa: F401 adds the routes to the blueprint
from app.integration import register_integration_blueprint_callback
from example.app.blueprint import example_bp
from saq.analysis.presenter.observable_presenter import register_observable_action
from saq.constants import F_TEST
from saq.gui.observable_actions.base import ObservableAction


def register_example_blueprint(flask_app: Flask):
    flask_app.register_blueprint(example_bp)

register_integration_blueprint_callback(register_example_blueprint)


class ObservableActionExample(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = "example"
        self.description = "Example Observable Action"
        self.action_path = 'example/observable_actions/example_action.html'
        self.icon = 'ok'

register_observable_action(F_TEST, ObservableActionExample)
