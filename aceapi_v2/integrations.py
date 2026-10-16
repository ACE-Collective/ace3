"""API routes an integration adds, served under /api/v2/integrations/<name>.

create_app() includes `router` once, under /integrations, and each integration's router is included
into it. An integration registers its router when its package is imported (through its
integration_<name>: block, see docs/INTEGRATIONS.md), during initialize_environment(), which can be
after an app was built: importing aceapi_v2 builds the module-level app. FastAPI resolves an
included router's routes when it serves a request, so an app also serves the routers registered
after it was built (tests/aceapi_v2/test_integrations.py checks).
"""

import re

from fastapi import APIRouter

_NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

router = APIRouter()

_ROUTERS: dict[str, APIRouter] = {}


def register_integration_router(name: str, integration_router: APIRouter) -> None:
    """Serve the router's routes under /api/v2/integrations/<name>.

    Every route requires a valid credential, as the core routes do; each one still needs its own
    require_permission() gate, which tests/saq/test_permission_catalog.py checks. Registering the
    same router under the same name again does nothing."""
    if not _NAME.match(name):
        raise ValueError(f"invalid integration router name {name!r}: use lowercase letters, digits and dashes")

    if name in _ROUTERS:
        if _ROUTERS[name] is integration_router:
            return

        raise ValueError(f"another router is already registered as integration {name!r}")

    _ROUTERS[name] = integration_router
    router.include_router(integration_router, prefix=f"/{name}")
