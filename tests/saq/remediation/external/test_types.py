import pytest

from saq.remediation.external.types import ProbeOutcome, ProbeOutcomeKind


@pytest.mark.unit
class TestProbeOutcome:

    def test_found_events_kind(self):
        outcome = ProbeOutcome(found_events=[{"x": 1}])
        assert outcome.kind is ProbeOutcomeKind.FOUND_EVENTS

    def test_not_found_kind(self):
        outcome = ProbeOutcome(not_found=True)
        assert outcome.kind is ProbeOutcomeKind.NOT_FOUND

    def test_pending_kind(self):
        outcome = ProbeOutcome(pending=True)
        assert outcome.kind is ProbeOutcomeKind.PENDING

    def test_transient_error_kind(self):
        outcome = ProbeOutcome(transient_error="boom")
        assert outcome.kind is ProbeOutcomeKind.TRANSIENT_ERROR

    def test_permanent_error_kind(self):
        outcome = ProbeOutcome(permanent_error="fatal")
        assert outcome.kind is ProbeOutcomeKind.PERMANENT_ERROR

    def test_zero_outcomes_rejected(self):
        with pytest.raises(ValueError):
            ProbeOutcome()

    def test_multiple_outcomes_rejected(self):
        with pytest.raises(ValueError):
            ProbeOutcome(pending=True, not_found=True)

    def test_empty_found_events_still_terminal(self):
        # An empty list is still "we got an answer, just nothing happened" —
        # the validator counts ``found_events is not None``, not truthiness.
        outcome = ProbeOutcome(found_events=[])
        assert outcome.kind is ProbeOutcomeKind.FOUND_EVENTS
