from saq.lazy_exports import lazy_getattr

# AnalysisModule is loaded the first time it is asked for (PEP 562), not when the package is: config
# parsing imports saq.modules.config, which needs only pydantic, and importing it here loaded the whole
# analysis framework into every process that reads its configuration
__getattr__ = lazy_getattr(__name__, {"AnalysisModule": "saq.modules.base_module"})
