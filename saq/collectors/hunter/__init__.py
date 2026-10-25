from saq.lazy_exports import lazy_getattr

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

__getattr__ = lazy_getattr(__name__, _EXPORTS)
