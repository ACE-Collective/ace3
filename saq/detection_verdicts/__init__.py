"""TP/FP verdicts on individual detections (docs/SVS.md, Part 1).

effective holds the rule that derives a detection's verdict and its source from the alert's
disposition and any stored override; query selects detections with that verdict; store writes and
clears overrides, recording each change in the verdict history.
"""
