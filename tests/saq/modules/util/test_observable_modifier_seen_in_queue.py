import uuid as uuid_lib

import pytest

from saq.analysis.analysis import Analysis
from saq.constants import F_EMAIL_ADDRESS, F_FQDN, F_URL
from saq.database.pool import get_db
from saq.database.model import Observable as DBObservable
from saq.database.util.alert import ALERT
from saq.database.util.observable_detection import create_observable_detection
from saq.database.util.queue_sighting import find_queue_sightings
from saq.modules.util.observable_modifier import (
    ObservableModifierAnalysis,
    RuleConditions,
    SeenInQueueCondition,
    _type_family,
)
from tests.saq.helpers import create_root_analysis
from tests.saq.modules.util.test_observable_modifier import _create_analyzer_with_rules

LURE = "lure.example.com"
INCIDENTAL = "login.microsoftonline.com"


class LookupAnalysis(Analysis):
    """stand-in for an analysis of the shared observable that a detection can sit on."""
    pass


def _alert(queue: str, value: str = LURE, o_type: str = F_FQDN, tags=(), observable_detection=False,
           analysis_detection=False, root_detection=False):
    """Creates and indexes an alert in queue holding one observable."""
    root = create_root_analysis(uuid=str(uuid_lib.uuid4()), queue=queue, analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(o_type, value)
    for tag in tags:
        observable.add_tag(tag)
    if observable_detection:
        observable.add_detection_point("observable hit")
    if analysis_detection:
        analysis = LookupAnalysis()
        observable.add_analysis(analysis)
        analysis.add_detection_point("analysis hit")
    if root_detection:
        root.add_detection_point("hunt matched")
    root.save()
    ALERT(root)
    return root


def _current(queue: str, value: str = LURE, o_type: str = F_FQDN, tags=()):
    """A root being analyzed now (not yet an alert), holding one observable."""
    root = create_root_analysis(uuid=str(uuid_lib.uuid4()), queue=queue, analysis_mode="test_single")
    root.initialize_storage()
    observable = root.add_observable_by_spec(o_type, value)
    for tag in tags:
        observable.add_tag(tag)
    return root, observable


def _rule(target_queue: str, tag: str, from_queue: str = None, **seen_kwargs):
    conditions = {
        "observable_types": [F_FQDN, F_URL],
        "seen_in_queue": {"queue": target_queue, "indicator_tags": ["intel_indicator"], **seen_kwargs},
    }
    if from_queue:
        conditions["queue"] = from_queue
    return {"name": f"seen in {target_queue}", "conditions": conditions, "actions": {"add_tags": [tag]}}


def _run_post(root, observable, rules):
    adapter = _create_analyzer_with_rules(root, rules)
    adapter.execute_analysis(observable)
    adapter.analyze(observable, final_analysis=True)
    return adapter


# ============================================================
# parsing / classification
# ============================================================


@pytest.mark.unit
def test_seen_in_queue_makes_rule_mutable():
    assert RuleConditions().is_immutable
    assert not RuleConditions(seen_in_queue=SeenInQueueCondition(queue="default")).is_immutable


@pytest.mark.unit
def test_seen_in_queue_parses_shorthand_and_mapping():
    root, _ = _current("intel")
    adapter = _create_analyzer_with_rules(root, [
        {"name": "short", "conditions": {"seen_in_queue": "default"}, "actions": {}},
        {"name": "long", "conditions": {"seen_in_queue": {
            "queue": "intel", "require_important": False, "indicator_tags": "intel_indicator"}}, "actions": {}},
        {"name": "missing queue", "conditions": {"seen_in_queue": {"require_important": False}}, "actions": {}},
    ])
    analyzer = adapter._module
    analyzer._ensure_initialized()
    analyzer._load_config()
    by_name = {rule.name: rule for rule in analyzer._rules}

    assert set(by_name) == {"short", "long"}
    assert by_name["short"].conditions.seen_in_queue == SeenInQueueCondition(queue="default")
    assert by_name["long"].conditions.seen_in_queue == SeenInQueueCondition(
        queue="intel", require_important=False, indicator_tags=["intel_indicator"])
    assert not by_name["short"].is_immutable


@pytest.mark.unit
@pytest.mark.parametrize("seen_in_queue", [
    {"queue": "default", "indicator_tag": ["intel_indicator"]},
    {"queue": "default", "require_important": "false"},
    {"queue": "default", "indicator_tags": [["intel_indicator"]]},
    {"queue": ["default"]},
    {"queue": ""},
    ["default"],
])
def test_malformed_seen_in_queue_skips_the_rule(seen_in_queue):
    """A typo must not quietly widen what the rule tags (a dropped indicator_tags, a truthy "false")."""
    root, _ = _current("intel")
    adapter = _create_analyzer_with_rules(root, [
        {"name": "malformed", "conditions": {"seen_in_queue": seen_in_queue}, "actions": {}},
    ])
    analyzer = adapter._module
    analyzer._ensure_initialized()
    analyzer._load_config()
    assert analyzer._rules == []


# ============================================================
# database lookup
# ============================================================


@pytest.mark.integration
def test_find_queue_sightings_finds_indicators_beyond_scan_limit():
    """An indicator is what the lookup exists to find, however many plain sightings are newer."""
    indicator = _alert("default", tags=["intel_indicator"])
    newer = _alert("default")

    root, observable = _current("intel")
    sightings = find_queue_sightings(
        [F_FQDN], observable.sha256_bytes, "default", root.uuid, ["intel_indicator"], scan_limit=1)

    assert sightings.truncated
    assert [(s.alert_uuid, s.reasons) for s in sightings.alerts] == [
        (newer.uuid, []),
        (indicator.uuid, ["tag:intel_indicator"]),
    ]


@pytest.mark.integration
def test_find_queue_sightings_not_truncated_under_scan_limit():
    _alert("default")
    root, observable = _current("intel")
    sightings = find_queue_sightings([F_FQDN], observable.sha256_bytes, "default", root.uuid, [], scan_limit=2)
    assert not sightings.truncated
    assert len(sightings.alerts) == 1


@pytest.mark.integration
def test_find_queue_sightings_collects_evidence_per_alert():
    plain = _alert("default")
    tagged = _alert("default", tags=["intel_indicator"])
    observable_hit = _alert("default", observable_detection=True)
    analysis_hit = _alert("default", analysis_detection=True)
    root_hit = _alert("default", root_detection=True)
    other_queue = _alert("intel", tags=["intel_indicator"])

    root, observable = _current("intel")
    sightings = find_queue_sightings([F_FQDN], observable.sha256_bytes, "default", root.uuid, ["intel_indicator"])

    reasons = {s.alert_uuid: s.reasons for s in sightings.alerts}
    assert other_queue.uuid not in reasons
    assert reasons == {
        plain.uuid: [],
        tagged.uuid: ["tag:intel_indicator"],
        observable_hit.uuid: ["detection_point"],
        analysis_hit.uuid: ["detection_point"],
        # a root-level detection says the alert fired, not that this observable mattered
        root_hit.uuid: [],
    }
    assert sightings.global_reasons == []


@pytest.mark.integration
def test_find_queue_sightings_excludes_the_current_alert():
    current = _alert("default", tags=["intel_indicator"])
    sightings = find_queue_sightings(
        [F_FQDN], current.get_observable_by_spec(F_FQDN, LURE).sha256_bytes, "default", current.uuid, [])
    assert sightings.alerts == []


@pytest.mark.integration
def test_find_queue_sightings_global_reasons():
    _alert("default")
    root, observable = _current("intel")
    create_observable_detection(observable.type, observable.value, user_id=None)
    get_db().commit()
    get_db().query(DBObservable).filter(DBObservable.sha256 == observable.sha256_bytes).update({"is_interesting": True})
    get_db().commit()

    sightings = find_queue_sightings([F_FQDN], observable.sha256_bytes, "default", root.uuid, [])
    assert sightings.global_reasons == ["observable_detection", "is_interesting"]


@pytest.mark.integration
def test_find_queue_sightings_unknown_observable():
    root, observable = _current("intel", value="never-seen.example")
    sightings = find_queue_sightings([F_FQDN], observable.sha256_bytes, "default", root.uuid, [])
    assert sightings.alerts == []


# ============================================================
# rule behavior
# ============================================================


@pytest.mark.integration
def test_intel_indicator_seen_in_default_is_tagged():
    """intel -> default: the VTI lure is an intel indicator, the phishing email merely carried it."""
    phish = _alert("default")
    root, observable = _current("intel", tags=["intel_indicator"])

    _run_post(root, observable, [_rule("default", "seen_in_default_queue", from_queue="intel")])

    assert observable.has_tag("seen_in_default_queue")
    analysis = observable.get_and_load_analysis(ObservableModifierAnalysis)
    evidence = analysis.matched_rules[0]["evidence"]["seen_in_queue"]
    assert evidence["queue"] == "default"
    assert evidence["alert_count"] == 1
    assert evidence["alerts"] == [{"uuid": phish.uuid, "reasons": []}]
    assert evidence["current_reasons"] == ["tag:intel_indicator"]


@pytest.mark.integration
def test_default_alert_tagged_when_intel_alert_marked_it_an_indicator():
    """default -> intel: the importance comes from the historical intel alert's tag."""
    intel = _alert("intel", tags=["intel_indicator"])
    root, observable = _current("default")

    _run_post(root, observable, [_rule("intel", "seen_in_intel_queue", from_queue="default")])

    assert observable.has_tag("seen_in_intel_queue")
    evidence = observable.get_and_load_analysis(ObservableModifierAnalysis).matched_rules[0]["evidence"]
    assert evidence["seen_in_queue"]["alerts"] == [{"uuid": intel.uuid, "reasons": ["tag:intel_indicator"]}]
    assert evidence["seen_in_queue"]["current_reasons"] == []


@pytest.mark.integration
def test_historical_detection_on_the_observable_is_importance():
    _alert("default", observable_detection=True)
    root, observable = _current("intel")

    _run_post(root, observable, [_rule("default", "seen_in_default_queue")])
    assert observable.has_tag("seen_in_default_queue")


@pytest.mark.integration
def test_current_detection_on_the_observable_is_importance():
    _alert("intel")
    root, observable = _current("default")
    observable.add_detection_point("yara hit on this url")

    _run_post(root, observable, [_rule("intel", "seen_in_intel_queue")])
    assert observable.has_tag("seen_in_intel_queue")


@pytest.mark.integration
def test_incidental_overlap_is_not_tagged():
    """Shared, but important in neither alert: a root-level detection does not count."""
    _alert("default", value=INCIDENTAL, root_detection=True)
    root, observable = _current("intel", value=INCIDENTAL)

    _run_post(root, observable, [_rule("default", "seen_in_default_queue")])
    assert not observable.has_tag("seen_in_default_queue")


@pytest.mark.integration
def test_incidental_overlap_tagged_when_importance_not_required():
    _alert("default", value=INCIDENTAL)
    root, observable = _current("intel", value=INCIDENTAL)

    _run_post(root, observable, [_rule("default", "seen_in_default_queue", require_important=False)])
    assert observable.has_tag("seen_in_default_queue")


@pytest.mark.integration
def test_whitelisted_observable_never_matches():
    _alert("default", tags=["intel_indicator"])
    root, observable = _current("intel", tags=["intel_indicator"])
    observable.whitelist()

    _run_post(root, observable, [_rule("default", "seen_in_default_queue", require_important=False)])
    assert not observable.has_tag("seen_in_default_queue")


@pytest.mark.integration
def test_not_seen_in_queue_is_not_tagged():
    root, observable = _current("intel", value="only-here.example", tags=["intel_indicator"])

    _run_post(root, observable, [_rule("default", "seen_in_default_queue")])
    assert not observable.has_tag("seen_in_default_queue")


@pytest.mark.integration
def test_queue_condition_keeps_rule_one_directional():
    _alert("default", tags=["intel_indicator"])
    root, observable = _current("default", tags=["intel_indicator"])

    _run_post(root, observable, [_rule("default", "seen_in_default_queue", from_queue="intel")])
    assert not observable.has_tag("seen_in_default_queue")


@pytest.mark.integration
def test_sightings_lookup_shared_across_rules(monkeypatch):
    import saq.database.util.queue_sighting as queue_sighting

    _alert("default", tags=["intel_indicator"])
    root, observable = _current("intel")
    calls = {"n": 0}
    real = queue_sighting.find_queue_sightings

    def counting(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(queue_sighting, "find_queue_sightings", counting)
    rules = [_rule("default", "tag_one"), _rule("default", "tag_two")]
    rules[1]["name"] = "second"
    _run_post(root, observable, rules)

    assert observable.has_tag("tag_one") and observable.has_tag("tag_two")
    assert calls["n"] == 1


@pytest.mark.integration
def test_lookup_failure_leaves_the_shared_session_alone(monkeypatch):
    """Other modules' uncommitted work in the shared session survives a failed lookup."""
    from contextlib import contextmanager

    import saq.database.util.queue_sighting as queue_sighting
    from saq.database.model import Tag as DBTag

    real_private_transaction = queue_sighting.private_transaction
    lookup_sessions = []

    def broken_query(*args, **kwargs):
        raise RuntimeError("database down")

    @contextmanager
    def failing_private_transaction():
        with real_private_transaction() as session:
            lookup_sessions.append(session)
            monkeypatch.setattr(session, "query", broken_query)
            yield session

    monkeypatch.setattr(queue_sighting, "private_transaction", failing_private_transaction)
    root, observable = _current("intel", tags=["intel_indicator"])
    pending_name = f"pending_{uuid_lib.uuid4()}"
    get_db().add(DBTag(name=pending_name))

    _run_post(root, observable, [_rule("default", "seen_in_default_queue")])

    assert lookup_sessions and lookup_sessions[0] is not get_db()()
    assert not observable.has_tag("seen_in_default_queue")
    get_db().commit()
    assert get_db().query(DBTag).filter(DBTag.name == pending_name).one_or_none() is not None


@pytest.mark.unit
def test_type_family_spans_subtypes():
    family = _type_family("email_from")
    assert {"email_address", "email_from"} <= family
    assert "fqdn" not in family
    assert _type_family("not_a_registered_type") == {"not_a_registered_type"}


@pytest.mark.integration
def test_subtype_in_one_alert_matches_base_type_in_another():
    """A phish sender (email_from) is the same address as an intel email_address indicator."""
    intel = _alert("intel", value="lure@example.com", o_type=F_EMAIL_ADDRESS, tags=["intel_indicator"])
    root, observable = _current("default", value="lure@example.com", o_type="email_from")
    rule = _rule("intel", "seen_in_intel_queue")
    rule["conditions"]["observable_types"] = [F_EMAIL_ADDRESS]

    _run_post(root, observable, [rule])
    assert observable.has_tag("seen_in_intel_queue")
    evidence = observable.get_and_load_analysis(ObservableModifierAnalysis).matched_rules[0]["evidence"]
    assert evidence["seen_in_queue"]["alerts"] == [{"uuid": intel.uuid, "reasons": ["tag:intel_indicator"]}]


@pytest.mark.unit
def test_root_observable_condition():
    """The signatures rules mark only the alert's own (root-level) observables as intel indicators."""
    root, observable = _current("intel")
    analysis = LookupAnalysis()
    observable.add_analysis(analysis)
    derived = analysis.add_observable_by_spec(F_URL, "https://derived.example/")
    rule = {
        "name": "root-level indicator",
        "phase": "pre",
        "conditions": {"queue": "intel", "root_observable": True},
        "actions": {"add_tags": ["intel_indicator"]},
    }
    adapter = _create_analyzer_with_rules(root, [rule])
    adapter.execute_analysis(observable)
    adapter.execute_analysis(derived)

    assert observable.has_tag("intel_indicator")
    assert not derived.has_tag("intel_indicator")

    found = {
        "name": "found by analysis",
        "phase": "pre",
        "conditions": {"root_observable": False},
        "actions": {"add_tags": ["found"]},
    }
    adapter = _create_analyzer_with_rules(root, [found])
    adapter.execute_analysis(observable)
    adapter.execute_analysis(derived)
    assert not observable.has_tag("found")
    assert derived.has_tag("found")
    assert not RuleConditions(root_observable=True).is_immutable


@pytest.mark.unit
def test_truncated_lookup_is_flagged_in_evidence(monkeypatch):
    """alert_count is only a lower bound when the scan was capped, and the evidence says so."""
    import saq.database.util.queue_sighting as queue_sighting
    from saq.database.util.queue_sighting import QueueSighting, QueueSightings

    monkeypatch.setattr(queue_sighting, "find_queue_sightings", lambda *a, **k: QueueSightings(
        queue="default", alerts=[QueueSighting(alert_uuid="a")], truncated=True))
    root, observable = _current("intel", tags=["intel_indicator"])

    seen = SeenInQueueCondition(queue="default", indicator_tags=["intel_indicator"]).evaluate(observable, root)
    assert seen["truncated"] is True
    assert seen["alert_count"] == 1

    monkeypatch.setattr(queue_sighting, "find_queue_sightings", lambda *a, **k: QueueSightings(
        queue="default", alerts=[QueueSighting(alert_uuid="a")]))
    assert "truncated" not in SeenInQueueCondition(queue="default", indicator_tags=["intel_indicator"]).evaluate(
        observable, root, {})
