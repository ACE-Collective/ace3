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
    FILE = "file"                  # the file was gone and the pool did not have it
    MATCH_RECORD = "match_record"  # stored, but the match record was gone (the alert was archived)
    STORAGE = "storage"            # the CAS refused the bytes


LABEL_TP = VERDICT_TP
LABEL_FP = VERDICT_FP
# votes of the strongest strength present disagree; excluded from results until someone relabels
LABEL_CONFLICTED = "conflicted"
LABELS = (LABEL_TP, LABEL_FP, LABEL_CONFLICTED)

# the Label filter's value for a sample with no label (no contributing detection has a verdict)
LABEL_FILTER_NONE = "none"
