from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from saq.remediation import timeline
from saq.remediation.timeline import (
    RemediationEvent,
    gather_remediation_events,
    register_remediation_event_provider,
)

pytestmark = pytest.mark.unit


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


@contextmanager
def _temporary_provider_class():
    """Yield a fresh class registered as a provider, unregister on exit.

    Tests share global module state (``REGISTERED_REMEDIATION_PROVIDERS``);
    this fixture isolates each test.
    """
    class _TestProviderAnalysis:
        pass

    register_remediation_event_provider(_TestProviderAnalysis)
    try:
        yield _TestProviderAnalysis
    finally:
        timeline.REGISTERED_REMEDIATION_PROVIDERS.remove(_TestProviderAnalysis)


def _fake_root(*, analyses_by_class=None, observables=None):
    """Build a fake RootAnalysis for the aggregator.

    ``analyses_by_class``: dict mapping a registered provider class to a list
    of analysis instances of that class — these are what
    ``RootAnalysis.get_analysis_by_type(cls)`` returns.
    """
    root = MagicMock()
    by_class = dict(analyses_by_class or {})
    root.get_analysis_by_type.side_effect = lambda cls: list(by_class.get(cls, []))
    obs_list = list(observables or [])
    root.find_observables.side_effect = lambda criteria: [o for o in obs_list if criteria(o)]
    return root


def _provider_analysis(events_to_return):
    """A registered provider analysis instance: load_details() + get_remediation_events()."""
    a = MagicMock(spec=["load_details", "get_remediation_events"])
    a.load_details.return_value = True
    a.get_remediation_events.return_value = events_to_return
    return a


def _fake_email_delivery_observable(value: str):
    o = MagicMock()
    o.type = "email_delivery"
    o.value = value
    return o


def _fake_remediation(id: int, action: str = "remove", name: str = "office365_email", type_: str = "email_delivery", key: str = "<m@x>|u@x"):
    r = MagicMock()
    r.id = id
    r.action = action
    r.name = name
    r.type = type_
    r.key = key
    return r


def _fake_remediation_history(id: int, remediation_id: int, insert_date: datetime, result: str = "SUCCESS", status: str = "COMPLETED", message: str = ""):
    h = MagicMock()
    h.id = id
    h.remediation_id = remediation_id
    h.insert_date = insert_date
    h.result = result
    h.status = status
    h.message = message
    return h


def _patch_db(remediations: list, history: list):
    """Stub saq.database.pool.get_db so the aggregator's DB path uses these rows."""
    fake_db = MagicMock()

    rem_q = MagicMock()
    rem_q.filter.return_value = rem_q
    rem_q.all.return_value = remediations

    hist_q = MagicMock()
    hist_q.filter.return_value = hist_q
    hist_q.all.return_value = history

    def query_side_effect(model):
        return rem_q if model.__name__ == "Remediation" else hist_q

    fake_db.query.side_effect = query_side_effect
    return patch("saq.database.pool.get_db", return_value=fake_db)


# ---------------------------------------------------------------------------
# RemediationEvent dataclass
# ---------------------------------------------------------------------------

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

    def test_register_is_idempotent(self):
        class C: pass
        register_remediation_event_provider(C)
        register_remediation_event_provider(C)
        try:
            assert timeline.REGISTERED_REMEDIATION_PROVIDERS.count(C) == 1
        finally:
            timeline.REGISTERED_REMEDIATION_PROVIDERS.remove(C)

    def test_empty_registry_means_no_events_from_tree(self):
        # No registered providers, no observables -> empty result, no DB query.
        root = _fake_root()
        assert gather_remediation_events(root) == []

    def test_only_registered_provider_classes_are_inspected(self):
        # The whole point of the registry: load_details() is NOT called for
        # arbitrary analyses on the alert page, only for instances of
        # registered classes. An imposter that happens to have the right shape
        # but isn't registered must not be touched.
        ts = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        e = _ev("vendor", ts)
        registered = _provider_analysis([e])
        imposter = _provider_analysis([_ev("imposter", ts)])

        with _temporary_provider_class() as ProviderClass:
            class _UnregisteredClass:
                pass
            root = _fake_root(analyses_by_class={
                ProviderClass: [registered],
                _UnregisteredClass: [imposter],
            })
            result = gather_remediation_events(root)

        assert result == [e]
        # Critical assertion: never even touched
        imposter.load_details.assert_not_called()
        imposter.get_remediation_events.assert_not_called()


class TestGatherRemediationEvents:

    def test_provider_returning_empty_is_fine(self):
        with _temporary_provider_class() as ProviderClass:
            root = _fake_root(analyses_by_class={ProviderClass: [_provider_analysis([])]})
            assert gather_remediation_events(root) == []

    def test_provider_returning_none_is_handled(self):
        with _temporary_provider_class() as ProviderClass:
            root = _fake_root(analyses_by_class={ProviderClass: [_provider_analysis(None)]})
            assert gather_remediation_events(root) == []

    def test_calls_load_details_before_querying_events(self):
        # load_details() reads disk; details ARE the events. Order matters.
        ts = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        e = _ev("vendor", ts)
        call_order: list[str] = []

        class _FakeProviderInstance:
            def load_details(self):
                call_order.append("load_details")
                return True

            def get_remediation_events(self):
                call_order.append("get_remediation_events")
                return [e]

        with _temporary_provider_class() as ProviderClass:
            root = _fake_root(analyses_by_class={ProviderClass: [_FakeProviderInstance()]})
            result = gather_remediation_events(root)

        assert result == [e]
        assert call_order == ["load_details", "get_remediation_events"]

    def test_load_details_failure_skips_only_that_instance(self):
        ts = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        good_event = _ev("vendor", ts)
        good = _provider_analysis([good_event])

        broken = MagicMock(spec=["load_details", "get_remediation_events"])
        broken.load_details.side_effect = OSError("disk gone")
        broken.get_remediation_events.return_value = [_ev("never", ts)]

        with _temporary_provider_class() as ProviderClass:
            root = _fake_root(analyses_by_class={ProviderClass: [broken, good]})
            result = gather_remediation_events(root)

        assert result == [good_event]
        broken.get_remediation_events.assert_not_called()

    def test_provider_exception_is_swallowed(self):
        ts = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        good_event = _ev("vendor", ts)

        good = _provider_analysis([good_event])
        bad = MagicMock(spec=["load_details", "get_remediation_events"])
        bad.load_details.return_value = True
        bad.get_remediation_events.side_effect = RuntimeError("boom")

        with _temporary_provider_class() as ProviderClass:
            root = _fake_root(analyses_by_class={ProviderClass: [bad, good]})
            assert gather_remediation_events(root) == [good_event]

    def test_non_remediation_event_objects_are_dropped(self):
        ts = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        good_event = _ev("vendor", ts)
        provider = _provider_analysis([good_event, {"not": "an event"}])

        with _temporary_provider_class() as ProviderClass:
            root = _fake_root(analyses_by_class={ProviderClass: [provider]})
            assert gather_remediation_events(root) == [good_event]


class TestSorting:

    def test_events_sorted_ascending_by_timestamp_when_event_time_missing(self):
        t1 = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        t3 = datetime(2026, 5, 6, 13, 0, tzinfo=timezone.utc)

        e_late = _ev("vendor", t3, event_type="resolved", description="Resolved")
        e_mid = _ev("vendor", t2)
        e_early = _ev("microsoft_defender", t1, event_type="detected", description="Detected")

        with _temporary_provider_class() as ProviderClass:
            root = _fake_root(analyses_by_class={
                ProviderClass: [
                    _provider_analysis([e_late, e_mid]),
                    _provider_analysis([e_early]),
                ],
            })
            assert gather_remediation_events(root) == [e_early, e_mid, e_late]

    def test_events_sorted_by_event_time_primary(self):
        msg1_received = datetime(2026, 5, 6, 8, 0, tzinfo=timezone.utc)
        msg2_received = datetime(2026, 5, 6, 14, 0, tzinfo=timezone.utc)
        msg1_ts = datetime(2026, 5, 6, 18, 0, tzinfo=timezone.utc)
        msg2_ts = datetime(2026, 5, 6, 14, 30, tzinfo=timezone.utc)

        msg1_event = _ev("vendor", msg1_ts, event_time=msg1_received)
        msg2_event = _ev("vendor", msg2_ts, event_time=msg2_received)

        with _temporary_provider_class() as ProviderClass:
            root = _fake_root(analyses_by_class={
                ProviderClass: [_provider_analysis([msg2_event, msg1_event])],
            })
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
            root = _fake_root(analyses_by_class={
                ProviderClass: [_provider_analysis([e_third, e_first, e_second])],
            })
            assert gather_remediation_events(root) == [e_first, e_second, e_third]

    def test_events_without_event_time_go_to_the_end(self):
        received = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)
        anchored_ts = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        standalone_ts = datetime(2026, 5, 6, 11, 0, tzinfo=timezone.utc)

        anchored = _ev("vendor", anchored_ts, event_time=received)
        standalone = _ev("vendor", standalone_ts, event_time=None)

        with _temporary_provider_class() as ProviderClass:
            root = _fake_root(analyses_by_class={
                ProviderClass: [_provider_analysis([standalone, anchored])],
            })
            assert gather_remediation_events(root) == [anchored, standalone]

    def test_multiple_unanchored_events_still_sort_by_timestamp(self):
        t_late = datetime(2026, 5, 6, 13, 0, tzinfo=timezone.utc)
        t_early = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

        early = _ev("vendor", t_early, event_time=None)
        late = _ev("vendor", t_late, event_time=None)

        with _temporary_provider_class() as ProviderClass:
            root = _fake_root(analyses_by_class={
                ProviderClass: [_provider_analysis([late, early])],
            })
            assert gather_remediation_events(root) == [early, late]

    def test_target_breaks_ties_when_event_time_and_when_match(self):
        # Same phish hits two recipients; both are remediated at the same time.
        # Tertiary sort is by target (recipient) to keep alice's row above bob's.
        received = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)
        ts = datetime(2026, 5, 6, 12, 5, tzinfo=timezone.utc)

        bob = _ev("vendor", ts, event_time=received, target="bob@example.com")
        alice = _ev("vendor", ts, event_time=received, target="alice@example.com")

        with _temporary_provider_class() as ProviderClass:
            root = _fake_root(analyses_by_class={
                ProviderClass: [_provider_analysis([bob, alice])],
            })
            assert gather_remediation_events(root) == [alice, bob]

    def test_event_time_still_dominates_target(self):
        # Earlier event_time wins even if its target sorts later alphabetically.
        ts = datetime(2026, 5, 6, 12, 5, tzinfo=timezone.utc)
        early_received = datetime(2026, 5, 6, 8, 0, tzinfo=timezone.utc)
        late_received = datetime(2026, 5, 6, 14, 0, tzinfo=timezone.utc)

        zach_early = _ev("vendor", ts, event_time=early_received, target="zach@example.com")
        alice_late = _ev("vendor", ts, event_time=late_received, target="alice@example.com")

        with _temporary_provider_class() as ProviderClass:
            root = _fake_root(analyses_by_class={
                ProviderClass: [_provider_analysis([alice_late, zach_early])],
            })
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
            root = _fake_root(analyses_by_class={
                ProviderClass: [_provider_analysis([vendor_late, ace_early])],
            })
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
            root = _fake_root(analyses_by_class={
                ProviderClass: [_provider_analysis([bob, alice])],
            })
            assert gather_remediation_events(root) == [alice, bob]

    def test_event_time_truncates_rather_than_rounds(self):
        # 12.900000 renders as "12" and must stay above "13" — rounding would
        # push it to 13 and flip these rows.
        early = _ev("vendor", datetime(2026, 5, 6, 13, 0, tzinfo=timezone.utc),
                    event_time=datetime(2026, 5, 6, 12, 0, 12, 900000, tzinfo=timezone.utc))
        late = _ev("vendor", datetime(2026, 5, 6, 12, 30, tzinfo=timezone.utc),
                   event_time=datetime(2026, 5, 6, 12, 0, 13, 0, tzinfo=timezone.utc))

        with _temporary_provider_class() as ProviderClass:
            root = _fake_root(analyses_by_class={
                ProviderClass: [_provider_analysis([late, early])],
            })
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
            root = _fake_root(analyses_by_class={
                ProviderClass: [_provider_analysis([vendor, ace])],
            })
            assert gather_remediation_events(root) == [ace, vendor]

        # Reversed input yields the same rendering.
        ace, vendor = _pair()
        with _temporary_provider_class() as ProviderClass:
            root = _fake_root(analyses_by_class={
                ProviderClass: [_provider_analysis([ace, vendor])],
            })
            assert gather_remediation_events(root) == [ace, vendor]


# ---------------------------------------------------------------------------
# ACE's own remediations from the DB
# ---------------------------------------------------------------------------

class TestACEEmailRemediationEvents:

    def test_no_email_delivery_observables_means_no_db_query(self):
        root = _fake_root(observables=[])
        with _patch_db(remediations=[], history=[]):
            assert gather_remediation_events(root) == []

    def test_email_delivery_with_no_remediations_returns_empty(self):
        obs = _fake_email_delivery_observable("<m1@x>|u@x")
        root = _fake_root(observables=[obs])
        with _patch_db(remediations=[], history=[]):
            assert gather_remediation_events(root) == []

    def test_one_remediation_one_attempt_yields_one_event(self):
        obs = _fake_email_delivery_observable("<m1@x>|alice@x")
        rem = _fake_remediation(id=42, action="remove", name="office365_email", key="<m1@x>|alice@x")
        attempt_t = datetime(2026, 5, 6, 12, 30, tzinfo=timezone.utc)
        attempt = _fake_remediation_history(id=1, remediation_id=42, insert_date=attempt_t, result="SUCCESS")

        root = _fake_root(observables=[obs])
        alert_event_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

        with _patch_db(remediations=[rem], history=[attempt]):
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
        assert e.metadata["remediation_id"] == 42
        assert e.metadata["history_id"] == 1
        assert e.metadata["result"] == "SUCCESS"
        assert e.metadata["status"] == "COMPLETED"
        assert e.duration_display == "30m"

    def test_multi_recipient_phish_yields_one_event_per_recipient(self):
        # Same phish sent to two users; each user has their own email_delivery
        # observable, their own Remediation row, and their own history attempt.
        # Timeline should show 2 rows, sorted alphabetically by recipient (Target tiebreaker).
        alice_obs = _fake_email_delivery_observable("<phish@bad>|alice@x")
        bob_obs = _fake_email_delivery_observable("<phish@bad>|bob@x")

        # Both attempts at the SAME wall time -> Target column is the tiebreaker.
        ts = datetime(2026, 5, 6, 12, 30, tzinfo=timezone.utc)

        rem_alice = _fake_remediation(id=1, action="remove", key="<phish@bad>|alice@x")
        rem_bob = _fake_remediation(id=2, action="remove", key="<phish@bad>|bob@x")
        h_bob = _fake_remediation_history(id=20, remediation_id=2, insert_date=ts, result="SUCCESS")
        h_alice = _fake_remediation_history(id=10, remediation_id=1, insert_date=ts, result="SUCCESS")

        alert_event_time = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)
        root = _fake_root(observables=[alice_obs, bob_obs])

        # Provide history rows out of order; sort should still place alice first.
        with _patch_db(remediations=[rem_bob, rem_alice], history=[h_bob, h_alice]):
            events = gather_remediation_events(root, fallback_event_time=alert_event_time)

        assert len(events) == 2
        assert [e.target for e in events] == ["alice@x", "bob@x"]
        assert all(e.source == "ACE" for e in events)

    def test_one_remediation_multiple_attempts_yield_one_row_per_attempt(self):
        obs = _fake_email_delivery_observable("<m1@x>|u@x")
        rem = _fake_remediation(id=42, action="remove")

        t1 = datetime(2026, 5, 6, 12, 5, tzinfo=timezone.utc)
        t2 = datetime(2026, 5, 6, 12, 10, tzinfo=timezone.utc)
        t3 = datetime(2026, 5, 6, 12, 15, tzinfo=timezone.utc)

        history = [
            _fake_remediation_history(id=1, remediation_id=42, insert_date=t1, result="ERROR"),
            _fake_remediation_history(id=2, remediation_id=42, insert_date=t2, result="ERROR"),
            _fake_remediation_history(id=3, remediation_id=42, insert_date=t3, result="SUCCESS"),
        ]

        root = _fake_root(observables=[obs])
        with _patch_db(remediations=[rem], history=history):
            events = gather_remediation_events(root, fallback_event_time=t1)

        assert len(events) == 3
        assert [e.timestamp for e in events] == [t1, t2, t3]
        assert [e.metadata["history_id"] for e in events] == [1, 2, 3]
        assert events[2].description == "Remove (Success)"
        assert events[0].description == "Remove (Error)"

    def test_combines_with_analysis_tree_providers_and_sorts(self):
        obs = _fake_email_delivery_observable("<m1@x>|u@x")
        rem = _fake_remediation(id=42)

        ace_t1 = datetime(2026, 5, 6, 12, 10, tzinfo=timezone.utc)
        abn_ts = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        ace_t2 = datetime(2026, 5, 6, 12, 30, tzinfo=timezone.utc)
        alert_t = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)

        history = [
            _fake_remediation_history(id=1, remediation_id=42, insert_date=ace_t1, result="SUCCESS"),
            _fake_remediation_history(id=2, remediation_id=42, insert_date=ace_t2, result="SUCCESS"),
        ]

        vendor_event = _ev("vendor", abn_ts, event_time=alert_t,
                             event_type="auto_remediated", description="Auto-Remediated")

        with _temporary_provider_class() as ProviderClass:
            root = _fake_root(
                analyses_by_class={ProviderClass: [_provider_analysis([vendor_event])]},
                observables=[obs],
            )
            with _patch_db(remediations=[rem], history=history):
                events = gather_remediation_events(root, fallback_event_time=alert_t)

        assert len(events) == 3
        # All share the same event_time -> sorted by timestamp
        assert [e.source for e in events] == ["ACE", "vendor", "ACE"]

    def test_db_query_failure_does_not_break_analysis_tree_events(self):
        ts = datetime(2026, 5, 6, 12, 25, tzinfo=timezone.utc)
        e = _ev("vendor", ts)

        with _temporary_provider_class() as ProviderClass:
            root = _fake_root(
                analyses_by_class={ProviderClass: [_provider_analysis([e])]},
                observables=[_fake_email_delivery_observable("<m@x>|u@x")],
            )
            with patch("saq.database.pool.get_db", side_effect=RuntimeError("db down")):
                result = gather_remediation_events(root)

        assert result == [e]

    def test_unknown_action_or_result_falls_back_gracefully(self):
        obs = _fake_email_delivery_observable("<m1@x>|u@x")
        rem = _fake_remediation(id=42, action="")
        ts = datetime(2026, 5, 6, 12, 30, tzinfo=timezone.utc)
        h = _fake_remediation_history(id=1, remediation_id=42, insert_date=ts, result="")

        root = _fake_root(observables=[obs])
        with _patch_db(remediations=[rem], history=[h]):
            events = gather_remediation_events(root, fallback_event_time=None)

        assert len(events) == 1
        assert events[0].description == "Remediation"
        assert events[0].source == "ACE"
