from saq.lazy_exports import lazy_getattr

# saq.analysis imports nothing itself: importing any of its submodules (a presenter, the module path
# helpers) ran this init, and it loaded the whole analysis tree. These names stay importable from
# saq.analysis, each loaded the first time it is asked for (PEP 562).
_EXPORTS = {
    "Analysis": "saq.analysis.analysis",
    "UnknownAnalysis": "saq.analysis.analysis",
    "Observable": "saq.analysis.observable",
    "RootAnalysis": "saq.analysis.root",
}

__getattr__ = lazy_getattr(__name__, _EXPORTS)
