# The package init runs in every ACE process (initialize_integrations() imports it to run the
# registration hooks below), so it imports only what registering needs. The analyzer lives in
# example/modules.py, which the engine imports from its analysis_module_example block, and the
# blueprint in example/app/blueprint.py, which only the GUI imports (docs/IMPORTS.md).
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flask import Flask

from aceapi_v2.integrations import register_integration_router
from app.integration import register_integration_blueprint_callback
from saq.constants import F_TEST
from saq.analysis.presenter.observable_presenter import register_observable_action
from saq.gui.observable_actions.base import ObservableAction

def register_example_blueprint(flask_app: "Flask"):
    # imported here: the blueprint module imports Flask, which only the GUI loads
    import example.app.views
    from example.app.blueprint import example_bp
    flask_app.register_blueprint(example_bp)

register_integration_blueprint_callback(register_example_blueprint)

# API routes, served under /api/v2/integrations/example
register_integration_router("example", "example.api.router")

class ObservableActionExample(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = "example"
        self.description = "Example Observable Action"
        self.action_path = 'example/observable_actions/example_action.html'
        self.icon = 'ok'

register_observable_action(F_TEST, ObservableActionExample)
