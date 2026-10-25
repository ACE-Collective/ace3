import importlib

# saq.analysis imports nothing itself: importing any of its submodules (a presenter, the module path
# helpers) ran this init, and it loaded the whole analysis tree. These names stay importable from
# saq.analysis, each loaded the first time it is asked for (PEP 562).
_EXPORTS = {
    "Analysis": "saq.analysis.analysis",
    "UnknownAnalysis": "saq.analysis.analysis",
    "Observable": "saq.analysis.observable",
    "RootAnalysis": "saq.analysis.root",
}


def __getattr__(name: str):
    if name not in _EXPORTS:
        raise AttributeError(f"module 'saq.analysis' has no attribute {name!r}")

    value = getattr(importlib.import_module(_EXPORTS[name]), name)
    globals()[name] = value
    return value
