"""Wire schemas for SVS test runs."""

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from aceapi_v2.alerts.schemas import AlertRow
from saq.svs.constants import RUN_STATES, ObservationSource, RunState


class RunTargetRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=255, description="a test host, by its short or fully qualified name")
    username: Optional[str] = Field(default=None, max_length=255, description="the user the test runs as (user, DOMAIN\\user or user@domain); required when the test host lists its users")


class RunRegistrationRequest(BaseModel):
    test_guid: str = Field(min_length=1, max_length=36, description="the auto_generated_guid of a test in the Atomic Red Team catalog (/api/v2/svs/tests)")
    targets: list[RunTargetRequest] = Field(min_length=1, description="the test hosts the test runs on")
    launcher: str = Field(min_length=1, max_length=256, description="the name of the launcher registering the run")
    batch_id: Optional[str] = Field(default=None, min_length=1, max_length=256, description="a label shared by runs registered together")
    extra: dict[str, Any] = Field(default_factory=dict, description="anything else the launcher wants kept with the run; stored and shown on the run page, at most svs.runs.max_extra_bytes as JSON")


class RunExecutedRequest(BaseModel):
    exit_code: int = Field(description="the test's exit code; anything but 0 moves the run to error")
    error: Optional[str] = Field(default=None, max_length=8192, description="what went wrong, when the launcher knows; moves the run to error")


class RunTarget(BaseModel):
    hostname: str = Field(description="as registered")
    username: Optional[str] = Field(default=None, description="as registered")
    host: str = Field(description="the short host name, lower case")
    fqdn: Optional[str] = None
    user: Optional[str] = Field(default=None, description="the bare user name, lower case")


class RunLifecycle(BaseModel):
    """A run as the launcher's calls return it."""

    run_id: str = Field(description="the run's uuid")
    marker: str = Field(description="put this where the test's process telemetry shows it (docs/SVS_RUNS.md, *The marker*)")
    state: RunState
    test_guid: str
    platform: str = Field(description="the platform the run is on, an ATT&CK platform slug: its targets' test hosts' "
                                      "platform, else the test's only supported platform (docs/SVS_RUNS.md, "
                                      "*Registering a run*)")
    targets: list[RunTarget]
    observation_seconds: int = Field(description="how long after start the run waits for its alerts before it ends")
    attribution_seconds: int = Field(description="how long after start its alerts are still attributed to it")
    holds_host: bool = Field(description="the run holds its hosts until its attribution window ends, not its "
                                         "observation window (its test's settings)")
    created_at: datetime
    started_at: Optional[datetime] = None
    cleanup_at: Optional[datetime] = Field(default=None, description="when the launcher said the test's cleanup began")
    observation_ends_at: Optional[datetime] = None
    attribution_ends_at: Optional[datetime] = None
    error_reason: Optional[str] = None
    close_reason: Optional[str] = None


class HostHolder(BaseModel):
    """A run holding a test host (docs/SVS_RUNS.md, *One run per test host*)."""

    host: str = Field(description="the test host, by its short name")
    run_id: str = Field(description="the run holding it")
    state: RunState
    until: Optional[datetime] = Field(default=None, description="when its claim on the host ends; null while it hasn't started")


class RunValidationTarget(BaseModel):
    hostname: str = Field(description="as sent")
    username: Optional[str] = Field(default=None, description="as sent")
    accepted: bool = Field(description="the target is a test host and a user it lists")
    reason: Optional[str] = Field(default=None, description="why the target would be refused")
    test_host: Optional[str] = Field(default=None, description="the test host it names, by its short name")
    platform: Optional[str] = Field(default=None, description="that test host's platform")
    held_by: list[HostHolder] = Field(default_factory=list, description="the runs holding that test host")



class RunValidation(BaseModel):
    """What POST /api/v2/svs/runs/ would decide for the same body, decided without changing anything."""

    decision: Literal["accepted", "refused", "invalid", "host_busy"]
    status_code: int = Field(description="what registering would answer: 201, 403, 409 or 422")
    message: Optional[str] = Field(default=None, description="why the registration is invalid: the 422's detail")
    targets: list[RunValidationTarget] = Field(
        description="every target, judged as registering would; empty when the registration is invalid before its "
                    "targets are judged")
    platform: Optional[str] = Field(default=None, description="the platform the run would be on, when accepted")
    observation_seconds: Optional[int] = Field(default=None, description="when accepted")
    observation_source: Optional[ObservationSource] = Field(
        default=None, description="where the observation window comes from: override, expected or all_hunts")
    attribution_seconds: Optional[int] = Field(default=None, description="when accepted")
    holds_host: Optional[bool] = Field(default=None, description="when accepted: the run would hold its hosts until "
                                                                 "its attribution window ends")


#
# reading runs (svs:run_read)
#

class RunRow(BaseModel):
    """A run as the runs screen lists it."""

    run_id: str = Field(description="the run's uuid")
    state: RunState
    test_guid: str = Field(description="the catalog test (/api/v2/svs/tests/{guid})")
    test_name: Optional[str] = Field(default=None, description="from the catalog")
    technique: Optional[str] = Field(default=None, description="the test's ATT&CK technique, from the catalog")
    technique_name: Optional[str] = None
    platform: str = Field(description="the platform the run is on, an ATT&CK platform slug: its targets' test hosts' "
                                      "platform, else the test's only supported platform (docs/SVS_RUNS.md, "
                                      "*Registering a run*)")
    marker: str = Field(description="the run's marker; svs_marker in ACE's logs")
    targets: list[RunTarget]
    launcher: str
    batch_id: Optional[str] = None
    created_at: datetime = Field(description="when the run was registered")
    started_at: Optional[datetime] = None
    executed_at: Optional[datetime] = Field(default=None, description="when the launcher reported how the test executed")
    exit_code: Optional[int] = None
    cleanup_at: Optional[datetime] = Field(default=None, description="when the launcher said the test's cleanup began: "
                                                                     "detections after it are the cleanup's")
    ended_at: Optional[datetime] = None
    canceled_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    observation_ends_at: Optional[datetime] = Field(default=None, description="when a started run ends")
    attribution_ends_at: Optional[datetime] = Field(default=None, description="until when alerts are attributed to it")
    error_reason: Optional[str] = None
    close_reason: Optional[str] = None
    owner: Optional[str] = Field(default=None, description="the owner's username")
    reviewer: Optional[str] = Field(default=None, description="who reviewed it, by username")
    reviewed_at: Optional[datetime] = None
    changed_since_review: bool = Field(description="a late alert or a manual association came after the review")
    needs_attention: bool = Field(description="the run is in the Needs attention view (docs/SVS_API.md, *Runs*)")
    result_hit: int = Field(default=0, description="expected signatures that fired (docs/SVS_API.md, *Results*)")
    result_expected: int = Field(default=0, description="the expected signatures the result judged: hit, missing or possibly suppressed")
    result_missing: int = Field(default=0, description="expected signatures that didn't fire, possibly suppressed ones included")
    result_possibly_suppressed: int = Field(default=0)
    result_candidate: int = Field(default=0, description="signatures that fired and nobody has decided about")
    result_rejected: int = Field(default=0)
    result_ignored: int = Field(default=0)
    result_cleanup: int = Field(default=0, description="signatures that fired only during the test's cleanup")
    result_stale: bool = Field(default=False, description="the result is about to be recomputed")
    reviewed_hit: int = Field(default=0, description="result_hit as signed off at the run's latest review; 0 until it is reviewed")
    reviewed_expected: int = Field(default=0, description="result_expected as signed off")
    reviewed_missing: int = Field(default=0, description="result_missing as signed off, possibly suppressed ones included")
    reviewed_possibly_suppressed: int = Field(default=0, description="result_possibly_suppressed as signed off")
    alerts: int = Field(default=0, description="the alerts attributed to the run")
    marker_alerts: int = Field(default=0, description="of those, attributed by a marker")
    context_alerts: int = Field(default=0, description="of those, attributed by context alone (TEST?)")
    late_alerts: int = Field(default=0, description="of those, late")
    updated_at: datetime = Field(description="when the row last changed; the changed_since key. A change to its "
                                             "result or alerts doesn't change it: pull GET /svs/runs/results")


class ReviewBlockers(BaseModel):
    """What a review would answer 409 with right now (docs/SVS_API.md, *Run actions*)."""

    stale: bool = Field(description="the result is being recomputed, or was never computed")
    candidates: list[str] = Field(description="the undecided signature uuids")
    context_alerts: list[str] = Field(description="the alerts with context attributions neither kept nor marked not a test")


class RunDetail(RunRow):
    extra: Optional[dict[str, Any]] = Field(default=None, description="what the launcher sent with the registration")
    launcher_error: Optional[str] = Field(default=None, description="the error the launcher reported through executed")
    test_content_hash: str = Field(description="the test's content_hash when the run was registered")
    catalog_commit: str = Field(description="the catalog repository's commit when the run was registered")
    observation_seconds: int
    attribution_seconds: int
    holds_host: bool = Field(description="the run holds its hosts until its attribution window ends, not its "
                                         "observation window (its test's settings)")
    registered_by: Optional[str] = Field(default=None, description="the username of the key that registered it")
    review_blockers: Optional[ReviewBlockers] = Field(
        default=None, description="ended and reviewed runs: what stands in the way of a review; null for other states")
    log_search_url: Optional[str] = Field(
        default=None, description="the run's search in the site's log tooling, from svs.log_search_url; null when that isn't set")


class RunPage(BaseModel):
    data: list[RunRow]
    next_cursor: Optional[str] = None


class RunCount(BaseModel):
    count: int = Field(description="the runs the filters match")


class SuppressionShare(BaseModel):
    """How many of the expected signatures missing from reviewed runs were possibly suppressed: the
    trigger to revisit keeping the hunter from suppressing test targets (docs/SVS.md, Part 3, *Hunt
    suppression*). Read from every run's result as signed off."""

    missing: int = Field(description="expected signatures missing from the signed-off results, possibly suppressed ones included")
    possibly_suppressed: int = Field(description="of those, the possibly suppressed")
    share: Optional[float] = Field(default=None, description="possibly_suppressed / missing; null while nothing is missing")
    reviewed_runs: int = Field(description="the runs with a signed-off result")
    first_reviewed_at: Optional[datetime] = Field(default=None, description="when the first run was reviewed")
    trigger_reached: bool = Field(description="50 runs are reviewed, or 90 days passed since the first review")
    reconsider: bool = Field(description="the trigger is reached and more than 10% of the missing signatures were "
                                         "possibly suppressed: preventing suppression is worth reconsidering")


class RunBatch(BaseModel):
    """One batch_id over the runs the filters match: only those runs are counted."""

    batch_id: str
    runs: int
    states: dict[str, int] = Field(description="the runs per state, every state named")
    needs_attention: int = Field(description="the runs in the Needs attention view")
    first_created_at: datetime = Field(description="when its first run was registered")
    last_created_at: datetime = Field(description="when its latest run was registered; the batches are newest first by it")
    result_hit: int = Field(default=0, description="expected signatures that fired, summed over the runs")
    result_expected: int = Field(default=0, description="the expected signatures the results judged, summed")
    result_missing: int = Field(default=0, description="expected signatures that didn't fire, possibly suppressed "
                                                       "ones included, summed")
    result_candidate: int = Field(default=0, description="undecided signatures that fired, summed")


class RunBatchPage(BaseModel):
    data: list[RunBatch]
    next_cursor: Optional[str] = None


class RunEvent(BaseModel):
    """One row of a run's event log."""

    id: int = Field(description="the event's id; a run's events are in id order")
    run_id: str = Field(description="the run's uuid")
    kind: str = Field(description="what happened: registered, transition, launcher_call, ... (docs/SVS_API.md, *Run events*)")
    from_state: Optional[RunState] = None
    to_state: Optional[RunState] = None
    actor: str = Field(description="who did it: the caller's name, or svs for a timer")
    actor_user: Optional[str] = Field(default=None, description="the actor's username, when the actor is a user")
    details: Optional[dict[str, Any]] = Field(default=None, description="what the event carries; its shape depends on kind")
    created_at: datetime
    updated_at: datetime = Field(description="the feed's changed_since key")


class RunEventPage(BaseModel):
    data: list[RunEvent]
    next_cursor: Optional[str] = None


class RunResult(BaseModel):
    """One signature of a run's result (docs/SVS_RUNS.md, *Results*; docs/SVS_API.md, *Results*)."""

    id: int = Field(description="the row's id")
    run_id: str = Field(description="the run's uuid")
    signature_uuid: str
    signature_family: Optional[str] = Field(default=None, description="yara, hunt, builtin, ...")
    signature_name: Optional[str] = None
    status: Optional[str] = Field(
        default=None,
        description="hit, missing, possibly_suppressed, candidate, rejected, ignored or cleanup; null once the "
                    "signature left the live result and the row holds only the reviewed result")
    alert_count: int = Field(description="the run's attributed alerts that carry the signature")
    late_only: bool = Field(description="every attribution of it is late")
    context_only: bool = Field(description="every attribution of it is by context alone")
    content_hash: Optional[str] = Field(default=None, description="the rule's own content hash when the result was computed")
    suppressing_alert_uuid: Optional[str] = Field(
        default=None, description="possibly_suppressed: the hunt's latest alert within its suppression period")
    suppression_imprecise: bool = Field(
        description="the hunt groups or deduplicates its alerts, so that alert may not have suppressed the run's")
    reviewed_status: Optional[str] = Field(default=None, description="the status as signed off; null until the run is reviewed")
    reviewed_alert_count: Optional[int] = None
    reviewed_late_only: Optional[bool] = None
    reviewed_content_hash: Optional[str] = None
    updated_at: datetime = Field(description="the feed's changed_since key")


class RunResultPage(BaseModel):
    data: list[RunResult]
    next_cursor: Optional[str] = None
    stale: Optional[bool] = Field(
        default=None,
        description="one run's results only: something changed since the result was computed, and the timers "
                    "recompute it shortly")
    computed_at: Optional[datetime] = Field(default=None, description="one run's results only: when it was last computed")


class Attribution(BaseModel):
    """One detection of an alert attributed to a run, removed ones included (docs/SVS_API.md,
    *Attributions*)."""

    id: int = Field(description="the row's id")
    run_id: str = Field(description="the run's uuid")
    alert_uuid: str
    detection: str = Field(description="the detection's content_hash (its detection_points row)")
    signature_uuid: str
    signature_family: Optional[str] = None
    confidence: str = Field(description="marker or context; a person's association is marker")
    late: bool = Field(description="the alert's event came after the run's observation window")
    event_time: Optional[datetime] = Field(default=None, description="the alert's event time it was judged by; null "
                                                                     "for attributions written before it was kept")
    cleanup: bool = Field(description="its event time is at or after the run's cleanup_at: the test's cleanup caused it, "
                                      "so it is left out of the run's candidates and expectations")
    source: str = Field(description="router (the marker router) or manual (a person associated the alert)")
    scan_point: Optional[str] = Field(default=None, description="where the agreeing marker was found; null for context or manual")
    actor: str = Field(description="who attributed it: svs for the router, else the person")
    actor_user: Optional[str] = Field(default=None, description="the person's username")
    created_at: datetime
    removed_at: Optional[datetime] = Field(default=None, description="when it stopped holding; null while it holds")
    removed_by: Optional[str] = Field(default=None, description="svs (the router found it no longer applies) or the person who disassociated it")
    removed_by_user: Optional[str] = None
    removal_reason: Optional[str] = None
    kept_at: Optional[datetime] = Field(default=None, description="when a person kept this context attribution")
    kept_by_user: Optional[str] = None
    updated_at: datetime = Field(description="the feed's changed_since key")


class AttributionPage(BaseModel):
    data: list[Attribution]
    next_cursor: Optional[str] = None


class RunAlertDetection(BaseModel):
    """One detection of an alert the run holds or held, and its attribution to the run."""

    detection: str = Field(description="the detection's content_hash")
    description: Optional[str] = Field(default=None, description="null when the alert no longer has the detection")
    signature_uuid: Optional[str] = None
    signature_family: Optional[str] = None
    attribution: Optional[Attribution] = Field(
        default=None, description="its attribution to this run, removed or not; null when it never had one")


class RunAlert(BaseModel):
    """An alert attributed to the run, now or before (docs/SVS_API.md, *Run alerts*)."""

    alert_uuid: str
    alert: Optional[AlertRow] = Field(default=None, description="the alert as GET /api/v2/alerts lists it; null when it is gone")
    holds: bool = Field(description="some attribution of it to the run holds")
    confidence: Optional[str] = Field(
        default=None, description="of those that hold: marker when any is (a person's association is marker), else context")
    late: bool = Field(description="an attribution that holds is late")
    cleanup: bool = Field(description="every attribution that holds is the test's cleanup's")
    manual: bool = Field(description="an attribution that holds was made by a person")
    kept: bool = Field(description="a person kept its context attributions")
    undecided_context: bool = Field(
        description="it has a context attribution that holds and nobody kept: a review waits for keep or not-a-test")
    detections: list[RunAlertDetection] = Field(description="every detection of the alert, and those it no longer has "
                                                            "that were attributed")


class RunAlertPage(BaseModel):
    data: list[RunAlert]
    next_cursor: Optional[str] = None


class HistoryRun(BaseModel):
    run_id: str
    state: RunState
    created_at: datetime
    reviewed_at: Optional[datetime] = None


class SignatureHistory(BaseModel):
    signature_uuid: str
    statuses: list[Optional[str]] = Field(
        description="its status in each of the runs, in their order: as reviewed for a reviewed run, else live; null "
                    "when it isn't in that run's result")


class RunHistory(BaseModel):
    """How the signatures of a run's result did in the test's earlier runs (docs/SVS_API.md, *Run history*)."""

    runs: list[HistoryRun] = Field(description="the test's ended and reviewed runs on this run's platform "
                                                    "registered before this one, newest first")
    signatures: list[SignatureHistory] = Field(description="one per signature of this run's result, in its order")


class AssociationRequest(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=4096, description="why, as the run's event log records it")


class AssociationResult(BaseModel):
    """What a person's association change left the alert with."""

    alert_uuid: str
    svs_status: Optional[str] = Field(default=None, description="test, test?, partial or mismatch; null for none")
    queue: str
    moved: bool = Field(description="the alert moved to another queue")
    reopened: bool = Field(description="the alert was SIMULATED and is OPEN again")


class BulkRunRequest(BaseModel):
    """A bulk action on runs, as the runs screen sends it."""

    run_ids: list[str] = Field(min_length=1, max_length=500, description="the runs' uuids")
    confirmed_takes: dict[str, str] = Field(
        default_factory=dict,
        description="run id -> the username of the person the caller agreed to take the run from; a run someone "
                    "else owns is left alone without it")
    reason: Optional[str] = Field(default=None, max_length=4096,
                                  description="close only: why; required for an ended run, which waits for a review")


class BulkRunResult(BaseModel):
    done: list[str] = Field(description="the runs the action was applied to")
    left_alone: dict[str, str] = Field(
        description="run id -> the username of whoever owns it, for the runs someone else owns; sent back as "
                    "confirmed_takes it takes them")
    conflicts: dict[str, str] = Field(description="run id -> why the action doesn't apply to it (its state, a missing reason)")
    unknown: list[str] = Field(description="run ids that don't exist")


class ReviewRequest(BaseModel):
    confirmed_take_from: Optional[str] = Field(
        default=None, description="the username of the run's owner the caller agreed to take it from, when someone else owns it")


class ReviewResult(BaseModel):
    run: RunDetail
    re_review: bool = Field(description="the run had been reviewed before; this sign-off replaces that one")
    counts: dict[str, int] = Field(description="signatures per result status, as signed off")
    alerts_closed: int = Field(description="alerts that became SIMULATED")
    fp_verdicts: int = Field(description="detections of ignored signatures given an FP verdict")


class RunCommentRequest(BaseModel):
    comment: str = Field(min_length=1, max_length=16384)


class RunComment(BaseModel):
    id: int
    run_id: str
    user: Optional[str] = Field(default=None, description="its author's username")
    comment: str
    created_at: datetime
    updated_at: datetime


RUN_ROW_CSV_FIELDS = tuple(RunRow.model_fields)
# the CSV spreads a batch's states over one column each
RUN_BATCH_CSV_FIELDS = tuple(
    column for name in RunBatch.model_fields
    for column in ([f"state_{state}" for state in RUN_STATES] if name == "states" else [name]))
RUN_EVENT_CSV_FIELDS = tuple(RunEvent.model_fields)
RUN_RESULT_CSV_FIELDS = tuple(RunResult.model_fields)
ATTRIBUTION_CSV_FIELDS = tuple(Attribution.model_fields)
