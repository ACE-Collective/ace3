from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import uuid

import pytest

from saq.analysis.analysis import Analysis
from saq.configuration.config import get_config
from saq.constants import F_EMAIL_DELIVERY, F_TEST
from saq.database.model import ExternalRemediationCheck, Remediation, RemediationHistory
from saq.database.pool import get_db
from saq.remediation import timeline
from saq.remediation.coverage import assemble_coverage
from saq.remediation.timeline import (
    RemediationEvent,
    gather_remediation_events,
    pending_events_from_coverage,
    register_remediation_event_provider,
)
from tests.saq.helpers import create_root_analysis


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _ev(source: str, ts: datetime, **overrides) -> RemediationEvent:
    base = dict(
        source=source,
        event_type="auto_remediated",
        timestamp=ts,
        description=f"{source}: Auto-Remediated",
    )
    base.update(overrides)
    return RemediationEvent(**base)


class _ProviderAnalysis(Analysis):
    """An Analysis that publishes the events it was built with."""

    def __init__(self, events=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events = events

    def get_remediation_events(self):
        return self.events


@contextmanager
def _temporary_provider_class():
    """Yield a fresh class registered as a provider, unregister on exit.

    Tests share global module state (``REGISTERED_REMEDIATION_PROVIDERS``);
    this fixture isolates each test.
    """
    class _TestProviderAnalysis(_ProviderAnalysis):
        pass

    register_remediation_event_provider(_TestProviderAnalysis)
    try:
        yield _TestProviderAnalysis
    finally:
        timeline.REGISTERED_REMEDIATION_PROVIDERS.remove(_TestProviderAnalysis)


def _root(*, analyses=(), email_deliveries=()):
    """A saved RootAnalysis with each analysis on its own observable, plus the given email_delivery observables."""
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    for index, analysis in enumerate(analyses):
        root.add_observable_by_spec(F_TEST, f"provider-{index}").add_analysis(analysis)
    for value in email_deliveries:
        root.add_observable_by_spec(F_EMAIL_DELIVERY, value)
    root.save()
    return root


def _remediation(key: str, action: str = "remove", name: str = "office365_email", type_: str = F_EMAIL_DELIVERY) -> Remediation:
    remediation = Remediation(type=type_, name=name, action=action, key=key, user_id=get_config().global_settings.automation_user_id)
    get_db().add(remediation)
    get_db().commit()
    return remediation


def _remediation_history(remediation: Remediation, insert_date: datetime, result: str = "SUCCESS", status: str = "COMPLETED", message: str = "") -> RemediationHistory:
    # TIMESTAMP columns hold naive datetimes, the way MySQL hands them back
    history = RemediationHistory(remediation_id=remediation.id, insert_date=insert_date.replace(tzinfo=None),
                                 result=result, status=status, message=message)
    get_db().add(history)
    get_db().commit()
    return history


# ---------------------------------------------------------------------------
# RemediationEvent dataclass
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestRemediationEvent:
    def test_required_fields(self):
        ts = datetime(2026, 5, 6, 12, 25, 29, tzinfo=timezone.utc)
        e = RemediationEvent(
            source="vendor", event_type="auto_remediated", timestamp=ts,
            description="Vendor: Auto-Remediated",
        )
        assert e.source == "vendor"
        assert e.actor is None
        assert e.target is None
        assert e.folder is None
        assert e.portal_url is None
        assert e.metadata == {}
        assert e.event_time is None
        assert e.duration is None
        assert e.duration_display is None

    def test_duration_with_event_time(self):
        ev_t = datetime(2026, 5, 6, 12, 0, 0, tzinfo=timezone.utc)
        ts = datetime(2026, 5, 6, 12, 25, 29, tzinfo=timezone.utc)
        e = RemediationEvent(
            source="vendor", event_type="auto_remediated", timestamp=ts,
            description="Auto-Remediated", event_time=ev_t,
        )
        assert e.duration == timedelta(minutes=25, seconds=29)
        assert e.duration_display == "25m 29s"

    def test_naive_datetimes_are_normalized_to_utc(self):
        # Regression: MySQL TIMESTAMP columns return naive datetimes; subtracting
        # them from a tz-aware event_time raises TypeError. RemediationEvent
        # normalizes both inputs to tz-aware UTC at construction time.
        naive_ts = datetime(2026, 5, 6, 12, 25, 29)            # no tzinfo
        aware_event_time = datetime(2026, 5, 6, 12, 0, 0, tzinfo=timezone.utc)
        e = RemediationEvent(
            source="ACE", event_type="ace_remove", timestamp=naive_ts,
            description="Remove (Failed)", event_time=aware_event_time,
        )
        assert e.timestamp.tzinfo is not None
        assert e.event_time.tzinfo is not None
        # And duration arithmetic now works without raising
        assert e.duration == timedelta(minutes=25, seconds=29)
        assert e.duration_display == "25m 29s"

    def test_naive_event_time_is_normalized_too(self):
        aware_ts = datetime(2026, 5, 6, 12, 25, 29, tzinfo=timezone.utc)
        naive_event_time = datetime(2026, 5, 6, 12, 0, 0)      # no tzinfo
        e = RemediationEvent(
            source="ACE", event_type="ace_remove", timestamp=aware_ts,
            description="Remove (Success)", event_time=naive_event_time,
        )
        assert e.duration == timedelta(minutes=25, seconds=29)

    @pytest.mark.parametrize("seconds,expected", [
        (0, "0s"),
        (-30, "0s"),
        (1, "1s"),
        (59, "59s"),
        (60, "1m"),
        (65, "1m 5s"),
        (3599, "59m 59s"),
        (3600, "1h"),
        (3661, "1h 1m"),
        (86399, "23h 59m"),
        (86400, "1d"),
        (90000, "1d 1h"),
        (172800, "2d"),
    ])
    def test_duration_display_formatting(self, seconds, expected):
        ev_t = datetime(2026, 5, 6, tzinfo=timezone.utc)
        ts = ev_t + timedelta(seconds=seconds)
        e = RemediationEvent(
            source="vendor", event_type="x", timestamp=ts,
            description="x", event_time=ev_t,
        )
        assert e.duration_display == expected


# ---------------------------------------------------------------------------
# Analysis-tree provider path
# ---------------------------------------------------------------------------

class TestProviderRegistry:

    @pytest.mark.unit
    def test_register_is_idempotent(self):
        class C: pass
        register_remediation_event_provider(C)
        register_remediation_event_provider(C)
        try:
            assert timeline.REGISTERED_REMEDIATION_PROVIDERS.count(C) == 1
        finally:
            timeline.REGISTERED_REMEDIATION_PROVIDERS.remove(C)

    @pytest.mark.integration
    def test_empty_registry_means_no_events_from_tree(self):
        # No registered providers, no observables -> empty result.
        root = _root()
        assert gather_remediation_events(root) == []

    @pytest.mark.integration
    def test_only_registered_provider_classes_are_inspected(self):
        # The whole point of the registry: load_details() is NOT called for
        # arbitrary analyses on the alert page, only for instances of
        # registered classes. An imposter that happens to have the right shape
        # but isn't registered must not be touched.
        ts = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        e = _ev("vendor", ts)
        touched: list[str] = []

        class _UnregisteredClass(Analysis):
            def load_details(self):
                touched.append("load_details")
                return super().load_details()

            def get_remediation_events(self):
                touched.append("get_remediation_events")
                return [_ev("imposter", ts)]

        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([e]), _UnregisteredClass()])
            result = gather_remediation_events(root)

        assert result == [e]
        # Critical assertion: never even touched
        assert touched == []


@pytest.mark.integration
class TestGatherRemediationEvents:

    def test_provider_returning_empty_is_fine(self):
        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([])])
            assert gather_remediation_events(root) == []

    def test_provider_returning_none_is_handled(self):
        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass(None)])
            assert gather_remediation_events(root) == []

    def test_calls_load_details_before_querying_events(self):
        # load_details() reads disk; details ARE the events. Order matters.
        ts = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        e = _ev("vendor", ts)
        call_order: list[str] = []

        with _temporary_provider_class() as ProviderClass:
            class _RecordingProvider(ProviderClass):
                def load_details(self):
                    call_order.append("load_details")
                    return super().load_details()

                def get_remediation_events(self):
                    call_order.append("get_remediation_events")
                    return super().get_remediation_events()

            root = _root(analyses=[_RecordingProvider([e])])
            result = gather_remediation_events(root)

        assert result == [e]
        assert call_order == ["load_details", "get_remediation_events"]

    def test_load_details_failure_skips_only_that_instance(self):
        ts = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        good_event = _ev("vendor", ts)
        asked: list[str] = []

        with _temporary_provider_class() as ProviderClass:
            class _BrokenProvider(ProviderClass):
                def load_details(self):
                    raise OSError("disk gone")

                def get_remediation_events(self):
                    asked.append("get_remediation_events")
                    return [_ev("never", ts)]

            root = _root(analyses=[_BrokenProvider(), ProviderClass([good_event])])
            result = gather_remediation_events(root)

        assert result == [good_event]
        assert asked == []

    def test_provider_exception_is_swallowed(self):
        ts = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        good_event = _ev("vendor", ts)

        with _temporary_provider_class() as ProviderClass:
            class _BadProvider(ProviderClass):
                def get_remediation_events(self):
                    raise RuntimeError("boom")

            root = _root(analyses=[_BadProvider(), ProviderClass([good_event])])
            assert gather_remediation_events(root) == [good_event]

    def test_non_remediation_event_objects_are_dropped(self):
        ts = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        good_event = _ev("vendor", ts)

        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([good_event, {"not": "an event"}])])
            assert gather_remediation_events(root) == [good_event]


@pytest.mark.integration
class TestSorting:

    def test_events_sorted_ascending_by_timestamp_when_event_time_missing(self):
        t1 = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        t3 = datetime(2026, 5, 6, 13, 0, tzinfo=timezone.utc)

        e_late = _ev("vendor", t3, event_type="resolved", description="Resolved")
        e_mid = _ev("vendor", t2)
        e_early = _ev("microsoft_defender", t1, event_type="detected", description="Detected")

        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([e_late, e_mid]), ProviderClass([e_early])])
            assert gather_remediation_events(root) == [e_early, e_mid, e_late]

    def test_events_sorted_by_event_time_primary(self):
        msg1_received = datetime(2026, 5, 6, 8, 0, tzinfo=timezone.utc)
        msg2_received = datetime(2026, 5, 6, 14, 0, tzinfo=timezone.utc)
        msg1_ts = datetime(2026, 5, 6, 18, 0, tzinfo=timezone.utc)
        msg2_ts = datetime(2026, 5, 6, 14, 30, tzinfo=timezone.utc)

        msg1_event = _ev("vendor", msg1_ts, event_time=msg1_received)
        msg2_event = _ev("vendor", msg2_ts, event_time=msg2_received)

        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([msg2_event, msg1_event])])
            assert gather_remediation_events(root) == [msg1_event, msg2_event]

    def test_timestamp_tiebreaks_within_same_event_time(self):
        received = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)
        ts_first = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        ts_second = datetime(2026, 5, 6, 12, 30, tzinfo=timezone.utc)
        ts_third = datetime(2026, 5, 6, 12, 45, tzinfo=timezone.utc)

        e_first = _ev("vendor", ts_first, event_time=received,
                      event_type="auto_remediated", description="Auto-Remediated")
        e_second = _ev("vendor", ts_second, event_time=received,
                       event_type="resolved", description="Resolved")
        e_third = _ev("vendor", ts_third, event_time=received,
                      event_type="reopened", description="Reopened")

        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([e_third, e_first, e_second])])
            assert gather_remediation_events(root) == [e_first, e_second, e_third]

    def test_events_without_event_time_go_to_the_end(self):
        received = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)
        anchored_ts = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        standalone_ts = datetime(2026, 5, 6, 11, 0, tzinfo=timezone.utc)

        anchored = _ev("vendor", anchored_ts, event_time=received)
        standalone = _ev("vendor", standalone_ts, event_time=None)

        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([standalone, anchored])])
            assert gather_remediation_events(root) == [anchored, standalone]

    def test_multiple_unanchored_events_still_sort_by_timestamp(self):
        t_late = datetime(2026, 5, 6, 13, 0, tzinfo=timezone.utc)
        t_early = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

        early = _ev("vendor", t_early, event_time=None)
        late = _ev("vendor", t_late, event_time=None)

        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([late, early])])
            assert gather_remediation_events(root) == [early, late]

    def test_target_breaks_ties_when_event_time_and_when_match(self):
        # Same phish hits two recipients; both are remediated at the same time.
        # Tertiary sort is by target (recipient) to keep alice's row above bob's.
        received = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)
        ts = datetime(2026, 5, 6, 12, 5, tzinfo=timezone.utc)

        bob = _ev("vendor", ts, event_time=received, target="bob@example.com")
        alice = _ev("vendor", ts, event_time=received, target="alice@example.com")

        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([bob, alice])])
            assert gather_remediation_events(root) == [alice, bob]

    def test_event_time_still_dominates_target(self):
        # Earlier event_time wins even if its target sorts later alphabetically.
        ts = datetime(2026, 5, 6, 12, 5, tzinfo=timezone.utc)
        early_received = datetime(2026, 5, 6, 8, 0, tzinfo=timezone.utc)
        late_received = datetime(2026, 5, 6, 14, 0, tzinfo=timezone.utc)

        zach_early = _ev("vendor", ts, event_time=early_received, target="zach@example.com")
        alice_late = _ev("vendor", ts, event_time=late_received, target="alice@example.com")

        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([alice_late, zach_early])])
            assert gather_remediation_events(root) == [zach_early, alice_late]

    def test_subsecond_event_time_does_not_override_when_tiebreak(self):
        # Each source resolves event_time from its own authority: a vendor probe
        # reports a whole second, while ACE's fallback carries microseconds
        # through its JSON round-trip. Both render as "17:05:13" in the table,
        # so the visible "When" column must decide the order.
        vendor_received = datetime(2026, 7, 8, 17, 5, 13, 0, tzinfo=timezone.utc)
        ace_received = datetime(2026, 7, 8, 17, 5, 13, 487000, tzinfo=timezone.utc)

        vendor_late = _ev("vendor", datetime(2026, 7, 8, 17, 22, 38, tzinfo=timezone.utc),
                          event_time=vendor_received)
        ace_early = _ev("ACE", datetime(2026, 7, 8, 17, 10, 29, tzinfo=timezone.utc),
                        event_time=ace_received)

        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([vendor_late, ace_early])])
            assert gather_remediation_events(root) == [ace_early, vendor_late]

    def test_subsecond_timestamp_does_not_override_target_tiebreak(self):
        # Same message, same displayed "When" — only microseconds differ. Target
        # (a visible column) breaks the tie, not the invisible sub-second part.
        received = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

        bob = _ev("vendor", datetime(2026, 5, 6, 12, 5, 0, tzinfo=timezone.utc),
                  event_time=received, target="bob@example.com")
        alice = _ev("vendor", datetime(2026, 5, 6, 12, 5, 0, 750000, tzinfo=timezone.utc),
                    event_time=received, target="alice@example.com")

        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([bob, alice])])
            assert gather_remediation_events(root) == [alice, bob]

    def test_event_time_truncates_rather_than_rounds(self):
        # 12.900000 renders as "12" and must stay above "13" — rounding would
        # push it to 13 and flip these rows.
        early = _ev("vendor", datetime(2026, 5, 6, 13, 0, tzinfo=timezone.utc),
                    event_time=datetime(2026, 5, 6, 12, 0, 12, 900000, tzinfo=timezone.utc))
        late = _ev("vendor", datetime(2026, 5, 6, 12, 30, tzinfo=timezone.utc),
                   event_time=datetime(2026, 5, 6, 12, 0, 13, 0, tzinfo=timezone.utc))

        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([late, early])])
            assert gather_remediation_events(root) == [early, late]

    def test_fully_tied_rows_order_deterministically_by_source(self):
        # Identical through target: source keeps the rendering stable even though
        # the aggregator's input order isn't (no ORDER BY on remediation_history).
        received = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)
        ts = datetime(2026, 5, 6, 12, 5, tzinfo=timezone.utc)

        def _pair():
            ace = _ev("ACE", ts, event_time=received, target="alice@example.com")
            vendor = _ev("vendor", ts, event_time=received, target="alice@example.com")
            return ace, vendor

        ace, vendor = _pair()
        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([vendor, ace])])
            assert gather_remediation_events(root) == [ace, vendor]

        # Reversed input yields the same rendering.
        ace, vendor = _pair()
        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([ace, vendor])])
            assert gather_remediation_events(root) == [ace, vendor]


# ---------------------------------------------------------------------------
# ACE's own remediations from the DB
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestACEEmailRemediationEvents:

    def test_no_email_delivery_observables_means_no_db_query(self):
        _remediation("<m1@x>|u@x")
        root = _root()
        with patch("saq.database.pool.get_db", wraps=get_db) as spy:
            assert gather_remediation_events(root) == []

        spy.assert_not_called()

    def test_email_delivery_with_no_remediations_returns_empty(self):
        root = _root(email_deliveries=["<m1@x>|u@x"])
        assert gather_remediation_events(root) == []

    def test_one_remediation_one_attempt_yields_one_event(self):
        rem = _remediation("<m1@x>|alice@x", action="remove", name="office365_email")
        attempt_t = datetime(2026, 5, 6, 12, 30, tzinfo=timezone.utc)
        attempt = _remediation_history(rem, attempt_t, result="SUCCESS")

        # rows the query must leave out: another observable type with the same key, and another message
        _remediation_history(_remediation("<m1@x>|alice@x", type_=F_TEST), attempt_t)
        _remediation_history(_remediation("<other@x>|alice@x"), attempt_t)

        root = _root(email_deliveries=["<m1@x>|alice@x"])
        alert_event_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

        events = gather_remediation_events(root, fallback_event_time=alert_event_time)

        assert len(events) == 1
        e = events[0]
        assert e.source == "ACE"
        assert e.event_type == "ace_remove"
        assert e.timestamp == attempt_t
        assert e.event_time == alert_event_time
        assert e.description == "Remove (Success)"
        assert e.actor == "office365_email"
        # Target parsed from `Remediation.key` (format: <msgid>|recipient)
        assert e.target == "alice@x"
        assert e.metadata["remediation_id"] == rem.id
        assert e.metadata["history_id"] == attempt.id
        assert e.metadata["result"] == "SUCCESS"
        assert e.metadata["status"] == "COMPLETED"
        assert e.duration_display == "30m"

    def test_multi_recipient_phish_yields_one_event_per_recipient(self):
        # Same phish sent to two users; each user has their own email_delivery
        # observable, their own Remediation row, and their own history attempt.
        # Timeline should show 2 rows, sorted alphabetically by recipient (Target tiebreaker).

        # Both attempts at the SAME wall time -> Target column is the tiebreaker.
        ts = datetime(2026, 5, 6, 12, 30, tzinfo=timezone.utc)

        # Insert bob's rows first; sort should still place alice first.
        rem_bob = _remediation("<phish@bad>|bob@x")
        rem_alice = _remediation("<phish@bad>|alice@x")
        _remediation_history(rem_bob, ts, result="SUCCESS")
        _remediation_history(rem_alice, ts, result="SUCCESS")

        alert_event_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)
        root = _root(email_deliveries=["<phish@bad>|alice@x", "<phish@bad>|bob@x"])

        events = gather_remediation_events(root, fallback_event_time=alert_event_time)

        assert len(events) == 2
        assert [e.target for e in events] == ["alice@x", "bob@x"]
        assert all(e.source == "ACE" for e in events)

    def test_one_remediation_multiple_attempts_yield_one_row_per_attempt(self):
        rem = _remediation("<m1@x>|u@x", action="remove")

        t1 = datetime(2026, 5, 6, 12, 5, tzinfo=timezone.utc)
        t2 = datetime(2026, 5, 6, 12, 10, tzinfo=timezone.utc)
        t3 = datetime(2026, 5, 6, 12, 15, tzinfo=timezone.utc)

        history = [
            _remediation_history(rem, t1, result="ERROR"),
            _remediation_history(rem, t2, result="ERROR"),
            _remediation_history(rem, t3, result="SUCCESS"),
        ]

        root = _root(email_deliveries=["<m1@x>|u@x"])
        events = gather_remediation_events(root, fallback_event_time=t1)

        assert len(events) == 3
        assert [e.timestamp for e in events] == [t1, t2, t3]
        assert [e.metadata["history_id"] for e in events] == [h.id for h in history]
        assert events[2].description == "Remove (Success)"
        assert events[0].description == "Remove (Error)"

    def test_combines_with_analysis_tree_providers_and_sorts(self):
        rem = _remediation("<m1@x>|u@x")

        ace_t1 = datetime(2026, 5, 6, 12, 10, tzinfo=timezone.utc)
        abn_ts = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        ace_t2 = datetime(2026, 5, 6, 12, 30, tzinfo=timezone.utc)
        alert_t = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

        _remediation_history(rem, ace_t1, result="SUCCESS")
        _remediation_history(rem, ace_t2, result="SUCCESS")

        vendor_event = _ev("vendor", abn_ts, event_time=alert_t,
                             event_type="auto_remediated", description="Auto-Remediated")

        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([vendor_event])], email_deliveries=["<m1@x>|u@x"])
            events = gather_remediation_events(root, fallback_event_time=alert_t)

        assert len(events) == 3
        # All share the same event_time -> sorted by timestamp
        assert [e.source for e in events] == ["ACE", "vendor", "ACE"]

    def test_db_query_failure_does_not_break_analysis_tree_events(self):
        ts = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        e = _ev("vendor", ts)

        with _temporary_provider_class() as ProviderClass:
            root = _root(analyses=[ProviderClass([e])], email_deliveries=["<m@x>|u@x"])
            with patch("saq.database.pool.get_db", side_effect=RuntimeError("db down")):
                result = gather_remediation_events(root)

        assert result == [e]

    def test_restore_attempt_is_described_by_its_action_and_result(self):
        rem = _remediation("<m1@x>|u@x", action="restore")
        ts = datetime(2026, 5, 6, 12, 30, tzinfo=timezone.utc)
        _remediation_history(rem, ts, result="FAILED", status="COMPLETED", message="mailbox locked")

        root = _root(email_deliveries=["<m1@x>|u@x"])
        events = gather_remediation_events(root, fallback_event_time=None)

        assert len(events) == 1
        assert events[0].description == "Restore (Failed)"
        assert events[0].event_type == "ace_restore"
        assert events[0].metadata["message"] == "mailbox locked"
        assert events[0].event_time is None
        assert events[0].duration_display is None


# ---------------------------------------------------------------------------
# Pending rows: one per email that is still outstanding
# ---------------------------------------------------------------------------

REAL_EMAIL = "<msg-1@example.com>|alice@example.com"
JOURNAL_REPORT = "<journal-1@example.com>|alice@example.com"
_ALERT = "alert-1"
# the coverage rows come from the database, which hands back naive datetimes
_T0 = datetime(2026, 5, 6, 12, 0)


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc)


def _pending_check(value, probe_name, update_time=None, insert_date=_T0, deadline=datetime(2026, 5, 13, 12, 0)):
    return ExternalRemediationCheck(
        id=1, probe_name=probe_name, observable_type=F_EMAIL_DELIVERY, observable_value=value, alert_uuid=_ALERT,
        status="IN_PROGRESS", result=None, result_message=None, events_json=None, update_time=update_time,
        insert_date=insert_date, deadline=deadline)


def _confirmed_check(value, probe_name):
    events_json = (
        '[{"source": "Vendor", "event_type": "auto_remediated", "timestamp": "2026-05-06T12:05:00Z",'
        ' "description": "Auto-Remediated", "target": "alice@example.com"}]')
    return ExternalRemediationCheck(
        id=2, probe_name=probe_name, observable_type=F_EMAIL_DELIVERY, observable_value=value, alert_uuid=_ALERT,
        status="COMPLETED", result="CONFIRMED", result_message=None, events_json=events_json, update_time=_T0,
        insert_date=_T0, deadline=_T0 + timedelta(days=7))


def _ace_remediation(status="IN_PROGRESS", result=None, action="remove", insert_date=_T0, update_time=None):
    return Remediation(type=F_EMAIL_DELIVERY, name="office365_email", key=REAL_EMAIL, status=status, result=result,
                       action=action, insert_date=insert_date, update_time=update_time)


def _coverage(targets, ace=None, checks=()):
    return assemble_coverage([_ALERT], {_ALERT: set(targets)}, ace or {}, {_ALERT: list(checks)})[_ALERT]


class TestPendingRows:

    @pytest.mark.unit
    def test_one_row_per_email_not_per_probe(self):
        last_checked = _T0 + timedelta(minutes=9)
        coverage = _coverage([JOURNAL_REPORT], checks=[
            _pending_check(JOURNAL_REPORT, "alpha", update_time=_T0 + timedelta(minutes=4)),
            _pending_check(JOURNAL_REPORT, "beta", update_time=last_checked, deadline=datetime(2026, 5, 14, 12, 0)),
        ])

        events = pending_events_from_coverage(coverage, fallback_event_time=_T0)

        assert len(events) == 1
        e = events[0]
        assert e.pending
        assert e.source == "Alpha, Beta"
        assert e.event_type == "watching"
        assert e.description == "Watching (until 2026-05-14 12:00:00 UTC)"
        assert e.target == "alice@example.com"
        assert e.timestamp == _utc(last_checked)
        assert e.event_time == _utc(_T0)
        assert e.metadata == {"email_delivery": JOURNAL_REPORT}
        # nothing has reacted to the message yet
        assert e.duration_display is None

    @pytest.mark.unit
    def test_email_confirmed_by_one_probe_has_no_row_while_a_sibling_still_polls(self):
        # two emails to the same recipient: the real one is confirmed by alpha while
        # beta still polls it; the journal report is watched by both
        coverage = _coverage([REAL_EMAIL, JOURNAL_REPORT], checks=[
            _confirmed_check(REAL_EMAIL, "alpha"),
            _pending_check(REAL_EMAIL, "beta"),
            _pending_check(JOURNAL_REPORT, "alpha"),
            _pending_check(JOURNAL_REPORT, "beta"),
        ])

        events = pending_events_from_coverage(coverage)

        assert [e.metadata["email_delivery"] for e in events] == [JOURNAL_REPORT]

    @pytest.mark.unit
    def test_never_attempted_check_uses_insert_date(self):
        coverage = _coverage([REAL_EMAIL], checks=[_pending_check(REAL_EMAIL, "alpha", insert_date=datetime(2026, 5, 6, 12, 1))])

        assert pending_events_from_coverage(coverage)[0].timestamp == datetime(2026, 5, 6, 12, 1, tzinfo=timezone.utc)

    @pytest.mark.unit
    def test_ace_removal_in_flight_reads_remediating(self):
        coverage = _coverage(
            [REAL_EMAIL],
            ace={REAL_EMAIL: [_ace_remediation(update_time=_T0 + timedelta(minutes=2))]},
            checks=[_pending_check(REAL_EMAIL, "alpha", update_time=_T0 + timedelta(minutes=1))],
        )

        events = pending_events_from_coverage(coverage)

        assert [(e.source, e.event_type, e.timestamp) for e in events] == [
            ("ACE, Alpha", "remediating", _utc(_T0 + timedelta(minutes=2))),
        ]
        assert events[0].description.startswith("Remediating (until ")

    @pytest.mark.unit
    def test_failed_ace_attempt_still_watched_keeps_its_row(self):
        coverage = _coverage(
            [REAL_EMAIL],
            ace={REAL_EMAIL: [_ace_remediation(status="COMPLETED", result="FAILED")]},
            checks=[_pending_check(REAL_EMAIL, "alpha")],
        )

        assert [e.source for e in pending_events_from_coverage(coverage)] == ["Alpha"]

    @pytest.mark.unit
    @pytest.mark.parametrize("ace_result", ["SUCCESS", "NOT_FOUND"])
    def test_email_ace_settled_has_no_row(self, ace_result):
        # removed by ACE, or not in the mailbox: nothing is outstanding even though a probe polls on
        coverage = _coverage(
            [REAL_EMAIL],
            ace={REAL_EMAIL: [_ace_remediation(status="COMPLETED", result=ace_result)]},
            checks=[_pending_check(REAL_EMAIL, "alpha")],
        )

        assert pending_events_from_coverage(coverage) == []

    @pytest.mark.unit
    def test_nothing_in_flight_means_no_rows(self):
        assert pending_events_from_coverage(_coverage([REAL_EMAIL])) == []

    @pytest.mark.integration
    def test_gather_lists_pending_rows_after_later_events(self):
        # the pending row's own timestamp is earlier than the failed attempt, and it
        # still reads last: what happened, then what is outstanding
        _remediation_history(_remediation(REAL_EMAIL), _T0 + timedelta(minutes=30), result="FAILED")
        coverage = _coverage([REAL_EMAIL], checks=[_pending_check(REAL_EMAIL, "alpha", update_time=_T0 + timedelta(minutes=5))])

        root = _root(email_deliveries=[REAL_EMAIL])
        events = gather_remediation_events(root, fallback_event_time=_utc(_T0), coverage=coverage)

        assert [(e.source, e.pending) for e in events] == [("ACE", False), ("Alpha", True)]

    @pytest.mark.integration
    def test_gather_without_coverage_has_no_pending_rows(self):
        assert gather_remediation_events(_root()) == []
