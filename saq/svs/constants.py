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
