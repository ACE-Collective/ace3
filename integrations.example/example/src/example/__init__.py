# The package init runs in every ACE process (initialize_integrations() imports it to run the
# registration hooks below), so it imports only what registering needs. The analyzer lives in
# example/modules.py, which the engine imports from its analysis_module_example block. The API router
# (example/api/router.py) and the GUI blueprint (example/app/blueprint.py) are named in the
# integration_example: block of etc/saq.integration.yaml, and only the API and the GUI import them
# (docs/IMPORTS.md).
from saq.constants import F_TEST
from saq.analysis.presenter.observable_presenter import register_observable_action
from saq.gui.observable_actions.base import ObservableAction

class ObservableActionExample(ObservableAction):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = "example"
        self.description = "Example Observable Action"
        self.action_path = 'example/observable_actions/example_action.html'
        self.icon = 'ok'

register_observable_action(F_TEST, ObservableActionExample)
