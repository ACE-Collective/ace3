from typing import Optional, Type, override

from saq import Analysis, AnalysisModule, Observable
from saq.constants import F_TEST, AnalysisExecutionResult

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
