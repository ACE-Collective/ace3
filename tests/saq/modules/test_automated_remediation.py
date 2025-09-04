import pytest
from saq.analysis import RootAnalysis
from saq.constants import F_EMAIL_DELIVERY
from saq.modules.remediation import AutomatedRemediationAnalyzer
from saq.modules.adapter import AnalysisModuleAdapter
from saq.remediation import RemediationTarget

@pytest.mark.unit
def test_automated_remediation_analyzer(test_context):
    # run the automated remediation analyzer on an email delivery observable
    observable = RootAnalysis().add_observable_by_spec(F_EMAIL_DELIVERY, '<test>|jdoe@company.com')
    analyzer = AnalysisModuleAdapter(AutomatedRemediationAnalyzer(context=test_context))
    analyzer.execute_analysis(observable)
    analysis = observable.get_analysis(analyzer.generated_analysis_type)

    # verify analysis is correct
    assert analysis.details['targets'][0]['type'] == 'email'
    assert analysis.details['targets'][0]['value'] == '<test>|jdoe@company.com'

    # verify remediation table is correct
    target = RemediationTarget('email', '<test>|jdoe@company.com')
    assert target.processing
