import importlib


# AnalysisModule is loaded the first time it is asked for (PEP 562), not when the package is: config
# parsing imports saq.modules.config, which needs only pydantic, and importing it here loaded the whole
# analysis framework into every process that reads its configuration
def __getattr__(name: str):
    if name != "AnalysisModule":
        raise AttributeError(f"module 'saq.modules' has no attribute {name!r}")

    value = importlib.import_module("saq.modules.base_module").AnalysisModule
    globals()[name] = value
    return value
