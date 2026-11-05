import json
from datetime import datetime, timedelta, timezone

import pytest

from saq.remediation.external.events import (
    events_from_check,
    summarize_alert_checks,
)
from saq.remediation.external.types import CheckResult, CheckStatus


def _confirmed_event_dict(**overrides):
    base = {
        "source": "fake",
        "event_type": "auto_remediated",
        "timestamp": "2026-05-13T12:00:00Z",
        "description": "Auto-Remediated",
        "event_time": "2026-05-13T11:55:00Z",
        "target": "alice@example.com",
    }
    base.update(overrides)
    return base


@pytest.mark.integration
def test_events_from_check_confirmed(make_check):
    check = make_check(
        status=CheckStatus.COMPLETED.value,
        result=CheckResult.CONFIRMED.value,
        events_json=json.dumps([_confirmed_event_dict()]),
    )
    events = events_from_check(check)

    assert len(events) == 1
    assert events[0].source == "fake"
    assert events[0].target == "alice@example.com"
    # ISO Z timestamps are normalized to tz-aware UTC.
    assert events[0].timestamp.tzinfo is not None


@pytest.mark.integration
def test_events_from_check_non_confirmed_returns_empty(make_check):
    pending = make_check(status=CheckStatus.NEW.value, result=None,
                         events_json=json.dumps([_confirmed_event_dict()]))
    assert events_from_check(pending) == []

    not_found = make_check(status=CheckStatus.COMPLETED.value,
                           result=CheckResult.NOT_FOUND.value,
                           events_json=json.dumps([_confirmed_event_dict()]))
    assert events_from_check(not_found) == []


@pytest.mark.integration
def test_events_from_check_malformed_json(make_check):
    check = make_check(status=CheckStatus.COMPLETED.value,
                       result=CheckResult.CONFIRMED.value,
                       events_json="not-json")
    assert events_from_check(check) == []


@pytest.mark.integration
def test_events_from_check_skips_bad_event_keeps_good(make_check):
    payload = [
        _confirmed_event_dict(timestamp="bogus"),       # bad
        _confirmed_event_dict(),                        # good
    ]
    check = make_check(status=CheckStatus.COMPLETED.value,
                       result=CheckResult.CONFIRMED.value,
                       events_json=json.dumps(payload))
    events = events_from_check(check)
    assert len(events) == 1


@pytest.mark.integration
def test_summarize_alert_checks_per_probe_split(make_check):
    confirmed = make_check(probe_name="vendor1",
                           status=CheckStatus.COMPLETED.value,
                           result=CheckResult.CONFIRMED.value)
    pending_a = make_check(probe_name="vendor1", retry_count=2,
                           update_time=datetime.now(timezone.utc) - timedelta(seconds=10))
    pending_d = make_check(probe_name="vendor2")

    footer = summarize_alert_checks(
        [confirmed, pending_a, pending_d],
        initial_retry_delay_seconds=60,
        max_retry_delay_seconds=3600,
    )

    by_probe = {e.probe_name: e for e in footer.entries}
    assert by_probe["vendor1"].confirmed == 1
    assert by_probe["vendor1"].pending == 1
    assert by_probe["vendor2"].pending == 1
    assert footer.any_pending is True


@pytest.mark.integration
def test_summarize_alert_checks_nothing_pending(make_check):
    assert summarize_alert_checks([]).entries == []

    finished = make_check(status=CheckStatus.COMPLETED.value, result=CheckResult.NOT_FOUND.value)
    footer = summarize_alert_checks([finished])
    assert [(e.probe_name, e.pending, e.not_found) for e in footer.entries] == [("fake_probe", 0, 1)]
    assert footer.any_pending is False
