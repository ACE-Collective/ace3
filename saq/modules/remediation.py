import logging
from saq.analysis import Analysis
from saq.analysis.observable import Observable
from saq.constants import AnalysisExecutionResult
from saq.configuration.config import get_config
from saq.modules import AnalysisModule
from saq.remediation.target import get_observable_remediation_targets
from saq.remediation.types import RemediationAction as RemediationActionType

KEY_TARGETS = "targets"

# TODO no reason this can't get the result of the remediation as well

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

    def execute_analysis(self, observable: Observable) -> AnalysisExecutionResult:
        analysis = self.create_analysis(observable)
        assert isinstance(analysis, RemediationAction)
        targets = get_observable_remediation_targets(observable)
        for target in targets:
            target.queue_remediation(RemediationActionType.REMOVE, get_config().global_settings.automation_user_id)
            analysis.targets.append({'name': target.remediator_name, 'type': target.observable_type, 'value': target.observable_value})
            logging.info(f"added auto-remediation entry for {target.remediator_name} {target.observable_type} {target.observable_value}")

        return AnalysisExecutionResult.COMPLETED
