"""The alert router registry: built-in routers plus the ones configured under alert_routers:.

route_alert() runs inside every alert insert (ALERT()) and every analysis pass over an alert,
in every process that does either (engine workers, collectors, the API, the GUI, the CLI), and
the GUI and API serve requests on many threads. So the registry is read without a lock and
replaced whole: loading builds a new tuple and swaps it in, and a reader sees the old routers or
the new ones, never an empty registry. Built-in routers are not part of what loading replaces.
"""

import importlib
import logging
import threading
from dataclasses import replace
from typing import Optional

from saq.alert_routing.detection_queue import DetectionQueueRouter
from saq.alert_routing.router import AlertRouter, RouteDecision, RouteStage
from saq.configuration.config import get_config
from saq.error.reporting import report_exception

_BUILTIN_ROUTERS: tuple[AlertRouter, ...] = (DetectionQueueRouter(),)

_lock = threading.Lock()
_registered: tuple[AlertRouter, ...] = ()
_load_errors: dict[str, str] = {}
_loaded = False


def _builtin_names() -> set[str]:
    return {router.name for router in _BUILTIN_ROUTERS}


def get_alert_routers() -> list[AlertRouter]:
    """Every router, in the order they run (ascending priority; built-ins first on a tie)."""
    routers = list(_BUILTIN_ROUTERS) + list(_registered)
    return sorted(routers, key=lambda router: router.priority)


def get_alert_router_load_errors() -> dict[str, str]:
    """The configured routers that failed to load, keyed on name."""
    return dict(_load_errors)


def load_alert_routers(force: bool = False) -> None:
    """Instantiate every router declared under alert_routers: (once per process)."""
    global _registered, _load_errors, _loaded
    if _loaded and not force:
        return

    with _lock:
        if _loaded and not force:
            return

        routers = []
        errors = {}
        for router_config in get_config().alert_routers:
            try:
                if router_config.name in _builtin_names():
                    raise ValueError(f"{router_config.name!r} is the name of a built-in router")
                module = importlib.import_module(router_config.python_module)
                cls = getattr(module, router_config.python_class)
                router = cls(name=router_config.name, priority=router_config.priority, **router_config.kwargs)
                if not isinstance(router, AlertRouter):
                    raise TypeError(f"{router_config.python_module}.{router_config.python_class} is not an AlertRouter")
                routers.append(router)
            except Exception as e:
                # one broken router must not stop the others, or any alert insert
                errors[router_config.name] = f"{type(e).__name__}: {e}"
                logging.error(
                    "failed to load alert router %s (%s.%s)",
                    router_config.name, router_config.python_module, router_config.python_class,
                    exc_info=True)

        _registered = tuple(routers)
        _load_errors = errors
        _loaded = True


def register_alert_router(router: AlertRouter) -> None:
    """Add a router to this process's registry, alongside the configured ones. For tests."""
    global _registered
    load_alert_routers()
    with _lock:
        if router.name in _builtin_names() or any(r.name == router.name for r in _registered):
            raise ValueError(f"an alert router named {router.name!r} is already registered")
        _registered = _registered + (router,)


def clear_alert_routers() -> None:
    """Remove every router that is not built in, and do not load the configured ones again.
    For tests."""
    global _registered, _load_errors, _loaded
    with _lock:
        _registered = ()
        _load_errors = {}
        _loaded = True


def reset_alert_routers() -> None:
    """Forget what was loaded, so the next route_alert() loads the configuration again. For tests."""
    global _registered, _load_errors, _loaded
    with _lock:
        _registered = ()
        _load_errors = {}
        _loaded = False


def route_alert(root, stage: RouteStage) -> Optional[RouteDecision]:
    """Run the routers in priority order and return the first decision, or None.

    A router that raises, or returns something that is not a RouteDecision, is reported and
    skipped: routing never breaks the alert insert or the analysis pass it runs inside.
    """
    load_alert_routers()
    for router in get_alert_routers():
        try:
            decision = router.route(root, stage)
            if decision is None:
                continue
            if not isinstance(decision, RouteDecision):
                raise TypeError(f"router {router.name!r} returned {decision!r}, not a RouteDecision")
        except Exception as e:
            logging.error(f"alert router {router.name} failed on {root}: {e}")
            report_exception()
            continue

        decision = replace(decision, router=router.name)
        logging.info(
            "alert router decided a queue",
            extra={"alert_uuid": root.uuid, "stage": stage.value, "router": router.name,
                   "queue": decision.queue, "reason": decision.reason})
        return decision

    return None
