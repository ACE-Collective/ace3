from saq.lazy_exports import lazy_getattr

# saq imports nothing itself, so importing one saq module costs only what that module imports. These
# names stay importable from saq for integrations (integrations.example uses them), each loaded the
# first time it is asked for (PEP 562).
_EXPORTS = {
    "Analysis": "saq.analysis.analysis",
    "Observable": "saq.analysis.observable",
    "RootAnalysis": "saq.analysis.root",
    "AnalysisModule": "saq.modules.base_module",
}

__getattr__ = lazy_getattr(__name__, _EXPORTS)
