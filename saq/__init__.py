import importlib

# saq imports nothing itself, so importing one saq module costs only what that module imports. These
# names stay importable from saq for integrations (integrations.example uses them), each loaded the
# first time it is asked for (PEP 562).
_EXPORTS = {
    "Analysis": "saq.analysis.analysis",
    "Observable": "saq.analysis.observable",
    "RootAnalysis": "saq.analysis.root",
    "AnalysisModule": "saq.modules.base_module",
}


def __getattr__(name: str):
    if name not in _EXPORTS:
        raise AttributeError(f"module 'saq' has no attribute {name!r}")

    value = getattr(importlib.import_module(_EXPORTS[name]), name)
    globals()[name] = value
    return value
