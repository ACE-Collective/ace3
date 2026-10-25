"""API routes an integration adds, served under /api/v2/integrations/<name>.

create_app() includes the router get_integrations_router() returns once, under /integrations, and each
integration's router is included into it. An integration registers its router when its package is
imported (through its integration_<name>: block, see docs/INTEGRATIONS.md), during
initialize_environment(), which can be after an app was built: importing aceapi_v2.application builds
its module-level app. FastAPI resolves an included router's routes when it serves a request, so an app
also serves the routers registered after it was built (tests/aceapi_v2/test_integrations.py checks).

Every ACE process imports the integrations, and so this module, but only the API serves their routes.
So an integration registers the name of the module that defines its router, and that module is
imported only once an API app is built.
"""

import importlib
import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import APIRouter

_NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

# integration name -> the name of the module that defines its `router`, or a router an integration
# imported itself
_ROUTERS: dict[str, "str | APIRouter"] = {}

# the router the apps serve under /integrations, built by the first create_app()
_router: "APIRouter | None" = None

# the integrations whose routers are in _router
_included: set[str] = set()


def register_integration_router(name: str, integration_router: "str | APIRouter") -> None:
    """Serve an integration's routes under /api/v2/integrations/<name>.

    integration_router is the name of the module that defines the integration's `router` (an
    APIRouter). It is imported when an API app is built, or now if one already was. A router object
    is accepted too, but importing it loads FastAPI and the router's whole service layer into every
    ACE process.

    Every route requires a valid credential, as the core routes do; each one still needs its own
    require_permission() gate, which tests/saq/test_permission_catalog.py checks. Registering the
    same router under the same name again does nothing."""
    if not _NAME.match(name):
        raise ValueError(f"invalid integration router name {name!r}: use lowercase letters, digits and dashes")

    if name in _ROUTERS:
        registered = _ROUTERS[name]
        if registered is integration_router or (isinstance(registered, str) and registered == integration_router):
            return

        raise ValueError(f"another router is already registered as integration {name!r}")

    _ROUTERS[name] = integration_router
    if _router is not None:
        _include(name)


def get_integrations_router() -> "APIRouter":
    """The router create_app() serves under /integrations, with every registered integration's router in
    it. One whose module fails to import is logged and left out, so it cannot keep the API from starting."""
    global _router
    if _router is None:
        # imported here, not at module level: every ACE process imports this module, and only the API
        # processes need FastAPI
        from fastapi import APIRouter

        _router = APIRouter()

    for name in _ROUTERS:
        if name not in _included:
            _include(name)

    return _router


def _include(name: str) -> None:
    registered = _ROUTERS[name]
    if isinstance(registered, str):
        try:
            integration_router = importlib.import_module(registered).router
        except Exception:
            logging.exception("unable to load the API router of integration %s from %s", name, registered,
                              extra={"integration": name, "python_module": registered})
            return
    else:
        integration_router = registered

    _router.include_router(integration_router, prefix=f"/{name}")
    _included.add(name)
