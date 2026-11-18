"""Verifies that confirmed external-check rows surface through the alert-page
timeline aggregator (the new third source added to ``gather_remediation_events``)."""
import json

import pytest

from saq.remediation.external.types import CheckResult, CheckStatus
from saq.remediation.timeline import gather_remediation_events


def _confirmed_event(**overrides):
    base = {
        "source": "fake",
        "event_type": "auto_remediated",
        "timestamp": "2026-05-13T12:00:00Z",
        "description": "Auto-Remediated",
        "target": "alice@example.com",
    }
    base.update(overrides)
    return base


class _RootStub:
    """RootAnalysis stand-in for the aggregator: only `uuid` and the
    observable / analysis-tree accessors are touched."""
    def __init__(self, uuid):
        self.uuid = uuid

    def find_observables(self, _predicate):
        return []

    def get_analysis_by_type(self, _cls):
        return []


@pytest.mark.integration
def test_gather_picks_up_confirmed_external_check(make_check, db_alert):
    make_check(
        status=CheckStatus.COMPLETED.value,
        result=CheckResult.CONFIRMED.value,
        events_json=json.dumps([_confirmed_event()]),
    )

    events = gather_remediation_events(_RootStub(db_alert.uuid))
    sources = [e.source for e in events]
    assert "fake" in sources
