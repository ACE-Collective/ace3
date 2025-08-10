import logging
from typing import Optional, Type, override

from flask import Blueprint, Flask
from app.integration import register_integration_blueprint_callback
from saq import Analysis, AnalysisModule, Observable
from saq.constants import F_TEST, AnalysisExecutionResult
from saq.analysis.presenter.observable_presenter import register_observable_action
from saq.gui.observable_actions.base import ObservableAction

KEY_RESULT = "result"

class ExampleAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_RESULT: None
        }
    
    @property
    def result(self) -> Optional[str]:
        return self.details.get(KEY_RESULT)

    @result.setter
    def result(self, value: str):
        self.details[KEY_RESULT] = value

    @override
    def generate_summary(self) -> Optional[str]:
        if self.result:
            return f"Example Analysis: {self.result}"
        else:
            return None

class ExampleAnalyzer(AnalysisModule):

    @override
    @property
    def valid_observable_types(self) -> list[str]:
        return [F_TEST]

    @override
    @property
    def generated_analysis_type(self) -> Optional[Type[Analysis]]:
        return ExampleAnalysis
    
    @override
    def execute_analysis(self, observable: Observable) -> AnalysisExecutionResult:
        analysis = self.create_analysis(observable)
        analysis.result = "Example Analysis Result"
        return AnalysisExecutionResult.COMPLETED

example_bp = Blueprint('example', __name__, url_prefix='/example', template_folder="templates")

def register_example_blueprint(flask_app: Flask):
    import example.app.views
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