"""The values a detection's verdict and its source take (docs/SVS.md, Part 1). Kept free of
imports so the filter validators in saq/gui can use them."""

VERDICT_TP = "tp"
VERDICT_FP = "fp"
VERDICTS = (VERDICT_TP, VERDICT_FP)

# an analyst set it, or confirmed an inherited TP
SOURCE_EXPLICIT = "explicit"
# inherited from the alert, which stated it for this detection: an FP alert, or a TP alert all of
# whose detections come from one signature
SOURCE_INHERITED_SINGLE = "inherited_single"
# inherited TP on an alert where several signatures fired, which nobody has confirmed: the weakest
# source, reported separately (docs/SVS.md, DP-2)
SOURCE_INHERITED_MULTI = "inherited_multi"
SOURCES = (SOURCE_EXPLICIT, SOURCE_INHERITED_SINGLE, SOURCE_INHERITED_MULTI)
