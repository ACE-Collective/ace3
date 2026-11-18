"""Unit tests for ``saq.modules.email.address``."""

from unittest.mock import MagicMock

import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import (
    ANALYSIS_MODULE_EMAIL_ADDRESS_FQDN_ANALYZER,
    AnalysisExecutionResult,
    F_EMAIL_ADDRESS,
    F_FQDN,
)
from saq.modules.email.address import EmailAddressFQDNAnalysis, EmailAddressFQDNAnalyzer
from tests.saq.helpers import create_root_analysis


@pytest.mark.unit
def test_analysis_initial_state():
    analysis = EmailAddressFQDNAnalysis()
    assert analysis.domain is None
    assert analysis.generate_summary() is None


@pytest.mark.unit
def test_analysis_summary_after_set():
    analysis = EmailAddressFQDNAnalysis()
    analysis.domain = "example.com"
    assert "example.com" in analysis.generate_summary()


@pytest.mark.unit
def test_analyzer_normalizes_case(test_context):
    """EmailAddressObservable lowercases on assignment, so the extracted domain should be lowercase too."""
    root = create_root_analysis()
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_EMAIL_ADDRESS, "User@Example.COM")

    analyzer = EmailAddressFQDNAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_EMAIL_ADDRESS_FQDN_ANALYZER),
    )
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED

    analysis = observable.get_analysis(EmailAddressFQDNAnalysis)
    assert analysis is not None
    assert analysis.domain == "example.com"

    fqdn = analysis.get_observable_by_type(F_FQDN)
    assert fqdn is not None
    assert fqdn.value == "example.com"
    assert fqdn.volatile is True


@pytest.mark.unit
def test_analyzer_returns_completed_with_no_analysis_on_no_domain(test_context):
    """If get_email_domain returns None (no @ in value), analyzer should bail without creating an analysis."""
    root = create_root_analysis()
    root.initialize_storage()

    # EmailAddressObservable rejects values without @, so use a stub to exercise the defensive branch.
    observable = MagicMock()
    observable.value = "no-at-symbol"

    analyzer = EmailAddressFQDNAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_EMAIL_ADDRESS_FQDN_ANALYZER),
    )
    analyzer.root = root

    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    # No call to create_analysis means observable.get_analysis was never reached.
    observable.get_analysis.assert_not_called()
