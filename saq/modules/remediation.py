import logging
from saq.analysis import Analysis
from saq.constants import AnalysisExecutionResult
from saq.environment import get_global_runtime_settings
from saq.modules import AnalysisModule
from saq.remediation import REMEDIATION_ACTION_REMOVE
from saq.observables import create_observable

KEY_TARGETS = "targets"

class RemediationAction(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_TARGETS: [],
        }

    @property
    def targets(self) -> list[dict]:
        return self.details[KEY_TARGETS]

    @targets.setter
    def targets(self, value: list[dict]):
        self.details[KEY_TARGETS] = value

    def generate_summary(self):
        return f'Automated Remediation - queued {len(self.details["targets"])} targets for removal'

class AutomatedRemediationAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return RemediationAction

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        analysis = self.create_analysis(observable)
        assert isinstance(analysis, RemediationAction)
        targets = create_observable(observable.type, observable.value).remediation_targets
        for target in targets:
            target.queue(REMEDIATION_ACTION_REMOVE, get_global_runtime_settings().automation_user_id)
            analysis.targets.append({'type': target.type, 'value': target.value})
            logging.info(f"Added auto-remediation entry for {target.type}|{target.value}")

        return AnalysisExecutionResult.COMPLETED
