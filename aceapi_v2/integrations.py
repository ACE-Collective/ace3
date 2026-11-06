"""API routes an integration adds, served under /api/v2/integrations/<name>.

create_app() includes the router get_integrations_router() returns once, under /integrations, and each
integration's router is included into it. An integration names the module that defines its router as
api_module in its integration_<name>: block (docs/INTEGRATIONS.md), and get_integrations_router()
registers it once the configuration is loaded, so only the API imports it.

An integration can also call register_integration_router() from its package init, which every ACE
process imports during initialize_environment(). That registers the name of the module, imported only
once an API app is built. Anything that calls create_app() before initialize_environment() built it
before that. FastAPI resolves an included router's routes when it serves a request, so an app also
serves the routers registered after it was built (tests/aceapi_v2/test_integrations.py checks).
"""

import importlib
import logging
import re
from typing import TYPE_CHECKING

from saq.configuration.config import get_config

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
    """The router create_app() serves under /integrations, with the router of every integration that
    declares an api_module, or registered one, in it. One whose module fails to import, or whose name
    cannot be a path segment, is logged and left out, so it cannot keep the API from starting."""
    global _router
    if _router is None:
        # imported here, not at module level: integrations that register their router from their
        # package init import this module in every ACE process, and only the API processes need FastAPI
        from fastapi import APIRouter

        _router = APIRouter()

    register_configured_integration_routers()

    for name in _ROUTERS:
        if name not in _included:
            _include(name)

    return _router


def register_configured_integration_routers() -> None:
    """Registers the api_module of every integration_<name>: block that declares one. One whose name
    cannot be a path segment is logged and left out."""
    for integration_config in get_config().integrations:
        if not integration_config.api_module:
            continue

        try:
            register_integration_router(integration_config.name, integration_config.api_module)
        except ValueError:
            logging.exception("unable to register the API router of integration %s from %s",
                              integration_config.name, integration_config.api_module,
                              extra={"integration": integration_config.name,
                                     "python_module": integration_config.api_module})


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
