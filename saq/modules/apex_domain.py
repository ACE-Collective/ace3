"""Adds the apex (registrable domain, eTLD+1) of a subdomain FQDN as an fqdn observable of its own.

``abc.example.com`` yields ``example.com``, so an analyst can pivot to every alert that involves
``example.com`` whatever subdomain it was reached through. The reduction is the one RDAP already
queries with (``saq.domain_similarity.registrable_domain``), and rdap_analyzer declares this module a
dependency so it looks the apex up once instead of once per subdomain.
"""

import logging
from typing import Optional

from saq.analysis.analysis import Analysis
from saq.constants import F_FQDN, AnalysisExecutionResult
from saq.modules import AnalysisModule

KEY_APEX_DOMAIN = "apex_domain"

DISPLAY_TYPE_APEX_DOMAIN = "Apex Domain"


def apex_domain_of(fqdn: str) -> Optional[str]:
    """The apex of ``fqdn``, or None when ``fqdn`` is already its own apex or has no public suffix."""
    # saq.domain_similarity loads tldextract, requests and jellyfish (~11 MB), and every process that reads an alert
    # imports this module to load ApexDomainAnalysis
    from saq.domain_similarity import registrable_domain

    normalized = (fqdn or "").strip().lower().rstrip(".")
    apex = registrable_domain(normalized)
    # registrable_domain falls back to its input when no public suffix is identifiable (bare
    # hostnames, internal names), which this comparison also rejects.
    if not apex or apex == normalized:
        return None
    return apex


class ApexDomainAnalysis(Analysis):
    """The apex domain of a subdomain FQDN."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {KEY_APEX_DOMAIN: None}

    @property
    def apex_domain(self) -> Optional[str]:
        return self.details[KEY_APEX_DOMAIN]

    @apex_domain.setter
    def apex_domain(self, value: str):
        self.details[KEY_APEX_DOMAIN] = value

    def generate_summary(self):
        if not self.apex_domain:
            return None
        return f"Apex Domain: {self.apex_domain}"


class ApexDomainAnalyzer(AnalysisModule):
    """Adds the apex domain of a subdomain fqdn observable as an fqdn observable."""

    @property
    def generated_analysis_type(self):
        return ApexDomainAnalysis

    @property
    def valid_observable_types(self):
        return F_FQDN

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        apex = apex_domain_of(observable.value)
        if apex is None:
            logging.debug(f"{observable.value} is its own apex or has no public suffix")
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(observable)
        assert isinstance(analysis, ApexDomainAnalysis)
        analysis.apex_domain = apex

        apex_observable = analysis.add_observable_by_spec(F_FQDN, apex, o_time=observable.time)
        if apex_observable is not None:
            apex_observable.display_type = DISPLAY_TYPE_APEX_DOMAIN

        return AnalysisExecutionResult.COMPLETED
