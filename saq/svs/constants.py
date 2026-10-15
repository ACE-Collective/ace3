"""The values of SVS sample data: a capture's state (docs/SVS_SAMPLES.md) and a sample's label
(docs/SVS.md, Part 2, *Labels*). Kept free of heavy imports so the filter validators in saq/gui
and the API can use them."""

from enum import StrEnum

from saq.detection_verdicts.constants import VERDICT_FP, VERDICT_TP


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
