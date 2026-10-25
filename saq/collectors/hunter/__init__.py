import importlib

# saq.collectors.hunter imports nothing itself: the svs service imports saq.collectors.hunter.loader to read
# hunt metadata, and this init loaded the whole hunter service with it. These names stay importable from
# saq.collectors.hunter, each loaded the first time it is asked for (PEP 562), which is how load_service()
# gets HunterService.
_EXPORTS = {
    "Hunt": "saq.collectors.hunter.base_hunter",
    "delete_persistence_data": "saq.collectors.hunter.base_hunter",
    "read_persistence_data": "saq.collectors.hunter.base_hunter",
    "write_persistence_data": "saq.collectors.hunter.base_hunter",
    "HuntManager": "saq.collectors.hunter.manager",
    "HunterService": "saq.collectors.hunter.service",
    "HunterCollector": "saq.collectors.hunter.service",
}


def __getattr__(name: str):
    if name not in _EXPORTS:
        raise AttributeError(f"module 'saq.collectors.hunter' has no attribute {name!r}")

    value = getattr(importlib.import_module(_EXPORTS[name]), name)
    globals()[name] = value
    return value
