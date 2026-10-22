"""The values of SVS sample data: a capture's state (docs/SVS_SAMPLES.md) and a sample's label
(docs/SVS.md, Part 2, *Labels*). Kept free of heavy imports so the filter validators in saq/gui
and the API can use them."""

from enum import StrEnum

from saq.detection_verdicts.constants import VERDICT_FP, VERDICT_TP
from saq.signatures.builtin import SVS_MARKER_MISMATCH, SVS_REGISTRATION_REFUSED


class CaptureState(StrEnum):
    PENDING = "pending"
    STORED = "stored"
    MISSING = "missing"


class MissingReason(StrEnum):
    FILE = "file"                  # the file was gone, or no longer had that sha256, and the pool did not have it
    MATCH_RECORD = "match_record"  # stored, but the match record was gone (the alert was archived)
    STORAGE = "storage"            # the CAS refused the bytes


LABEL_TP = VERDICT_TP
LABEL_FP = VERDICT_FP
# votes of the strongest strength present disagree; excluded from results until someone relabels
LABEL_CONFLICTED = "conflicted"
LABELS = (LABEL_TP, LABEL_FP, LABEL_CONFLICTED)

# the Label filter's value for a sample with no label (no contributing detection has a verdict)
LABEL_FILTER_NONE = "none"


class ValidationState(StrEnum):
    """Where a YARA validation is (docs/SVS_VALIDATION.md, *The svs service*)."""
    QUEUED = "queued"          # waiting for a service_svs worker
    RUNNING = "running"        # a worker holds its lease
    COMPLETED = "completed"    # its report is stored
    FAILED = "failed"          # it could not run; error says why


VALIDATION_STATES = tuple(state.value for state in ValidationState)


class RunState(StrEnum):
    """Where a test run is (docs/SVS_RUNS.md, *Run states and timers*)."""
    CREATED = "created"      # registered; the launcher has not called start
    STARTED = "started"      # the windows are open
    ENDED = "ended"          # the observation window passed; waits for a person
    REVIEWED = "reviewed"    # signed off; what coverage counts
    CANCELED = "canceled"    # stopped by the launcher; still attributes until its attribution window ends
    ERROR = "error"          # the launcher reported a failure, or never called start
    CLOSED = "closed"        # discarded: nothing is learned from it


RUN_STATES = tuple(state.value for state in RunState)


class RunEventKind(StrEnum):
    """The kinds of row in a run's event log (svs_run_events)."""
    REGISTERED = "registered"
    TRANSITION = "transition"
    LAUNCHER_CALL = "launcher_call"
    ATTRIBUTED = "attributed"                    # detections of an alert attributed to the run
    ATTRIBUTION_REMOVED = "attribution_removed"  # attributions that no longer hold
    ALERTS_CLOSED = "alerts_closed"              # the run's alerts given SIMULATED when it closed
    RESULT_COMPUTED = "result_computed"          # the run's result changed
    CANDIDATE_DECISION = "candidate_decision"    # a signature in the run's result was decided
    ASSOCIATED = "associated"                    # a person associated an alert with the run
    DISASSOCIATED = "disassociated"              # a person disassociated an alert (or marked it not a test)
    CONTEXT_KEPT = "context_kept"                # a person kept an alert's context attribution
    OWNERSHIP_TAKEN = "ownership_taken"          # a person took the run (from its owner, when it had one)
    REVIEWED = "reviewed"                        # a person signed the run's result off (again, for a re-review)


class ExpectationState(StrEnum):
    """A decision about a signature for a test (svs_expectations.state)."""
    EXPECTED = "expected"    # a run of the test should fire it
    REJECTED = "rejected"    # it fires, but it is not what the test is about; never proposed again


class IgnoreScope(StrEnum):
    """Which runs an ignore applies to (svs_ignores.scope)."""
    GLOBAL = "global"        # every test's runs (launcher noise); svs:admin
    TEST = "test"            # one test's runs; svs:run_manage


# svs_ignores.scope_key of a global ignore; a test's ignores carry its guid
GLOBAL_SCOPE_KEY = "global"


class ResultStatus(StrEnum):
    """One signature of a run's result (svs_run_results.status, docs/SVS_RUNS.md, *Results*)."""
    HIT = "hit"                                  # expected, and it fired
    MISSING = "missing"                          # expected, and it did not fire
    POSSIBLY_SUPPRESSED = "possibly_suppressed"  # missing, and its hunt alerted within its suppression period
    CANDIDATE = "candidate"                      # it fired, and nobody has decided about it yet
    REJECTED = "rejected"                        # it fired, and it was rejected for the test
    IGNORED = "ignored"                          # it fired, and it is ignored (globally or for the test)
    CLEANUP = "cleanup"                          # it fired only during the test's cleanup, and isn't expected


class ObservationSource(StrEnum):
    """Where a run's observation window came from (the registered event's observation_source)."""
    OVERRIDE = "override"    # the test's settings
    EXPECTED = "expected"    # the latency of the test's expected signatures
    ALL_HUNTS = "all_hunts"  # the test has no expectations yet: the slowest enabled hunt


class AttributionConfidence(StrEnum):
    """How an alert's detection was attributed to a run (svs_attributions.confidence)."""
    MARKER = "marker"        # a marker that agrees with the run: its run, its target, its window
    CONTEXT = "context"      # no marker at all: the run's target and window alone


class AttributionSource(StrEnum):
    """Who wrote an attribution (svs_attributions.source)."""
    ROUTER = "router"        # the marker router (saq/svs/routing.py)
    MANUAL = "manual"        # a person associated the alert with the run


class ScanPoint(StrEnum):
    """Where in an alert a marker was found (docs/SVS_RUNS.md, *Attribution*)."""
    OBSERVABLE = "observable"        # an observable's value, or a file observable's name
    DETECTION = "detection"          # a detection's description or details
    ROOT_DETAILS = "root_details"    # the alert's own details: hunt events, API details
    ANALYSIS = "analysis"            # the details of a module's analysis (saved by the executor)
    FILE_CONTENTS = "file_contents"  # the SVS_Marker YARA rule matched a file (saq/svs/marker_rule.py)


class MarkerResult(StrEnum):
    """What a marker found in an alert says about it (docs/SVS.md, Part 3, *Markers*)."""
    ATTRIBUTED = "attributed"            # it agrees with its run
    UNKNOWN = "unknown"                  # no run has it
    OTHER_HOST = "other host"            # the alert involves none of its run's targets
    OUTSIDE_WINDOW = "outside window"    # the run never started, or the event is outside its attribution window


class SVSStatus(StrEnum):
    """The one SVS status of an alert (docs/SVS.md, Part 3, *What analysts see*)."""
    TEST = "test"                        # every detection attributed by marker; routed to the test queue
    TEST_CONTEXT = "test?"               # attributed by context only; routed to the test queue
    PARTIAL = "partial"                  # some detections attributed; stays in its queue
    MISMATCH = "mismatch"                # a marker that doesn't agree with its context; stays in its queue


# the root extension the executor saves the markers it finds in analysis details to
SIGHTINGS_EXTENSION = "svs_sightings"

# the tags the svs_alert_tagger module puts on the root
TAG_SVS_TEST = "svs_test"
TAG_MARKER_MISMATCH = "svs:marker_mismatch"

# the actor of what the marker router writes
ROUTER_ACTOR = "svs"

# the router name (alert_queue_changes.router) of every queue move a person makes through SVS:
# associating an alert, or disassociating it. The marker router never moves an alert whose latest
# move is one of these (docs/SVS_RUNS.md, *Associating alerts by hand*)
SVS_MANUAL_ROUTER = "svs_manual"


class CoverageState(StrEnum):
    """Coverage of a technique on a platform (svs_coverage.state, docs/SVS_COVERAGE.md, *States*),
    worst first: a row is in the first state any test or mapping that counts toward it is in."""
    FAILING = "failing"        # a test's latest reviewed run there missed an expected signature
    STALE = "stale"            # validated, but the test, an expected rule or the expectations changed since
    VALIDATED = "validated"    # a test's latest reviewed run there hit every expected signature
    MANUAL = "manual"          # only a signature's mitre: tag claims it
    UNTESTED = "untested"      # tests exist, none judged there yet
    NONE = "none"              # no tests and no tags


# the actor of the refreshes service_svs runs
COVERAGE_ACTOR = "svs:coverage"


class WorklistKind(StrEnum):
    """What a declared-vs-measured worklist row is about (svs_technique_worklist.kind,
    docs/SVS_COVERAGE.md, *The worklist*)."""
    DECLARED = "declared"          # a mitre: tag of a measured signature
    UNDECLARED = "undeclared"      # a technique the signature is measured on that no tag of it covers
    UNKNOWN = "unknown"            # a mitre: tag naming an id the ATT&CK release doesn't have


class WorklistStatus(StrEnum):
    """Where a worklist row stands, derived on every refresh; only the resolution is stored."""
    CONFIRMED = "confirmed"            # what the tag claims is measured
    OPEN = "open"                      # not measured, not resolved
    KEPT = "kept"                      # resolved keep: it covers something no test reaches
    REMOVE_PENDING = "remove_pending"  # resolved remove, the tag is still there
    REMOVED = "removed"                # resolved remove, the tag is gone
    UNDECLARED = "undeclared"          # informational
    UNKNOWN = "unknown"                # informational
    RETIRED = "retired"                # the signature isn't measured any more, or the tag went away unresolved


class WorklistResolution(StrEnum):
    KEEP = "keep"
    REMOVE = "remove"


# the SVS built-ins are about runs, not detections a test fires: a refused registration names the
# test host, so context attribution would claim its alert for a run live there and hide it from
# triage. They are never attributed (saq/svs/attribution.py) and never counted in a result
RUN_SIGNATURES = frozenset({SVS_REGISTRATION_REFUSED.uuid, SVS_MARKER_MISMATCH.uuid})
