"""FastAPI application factory for the ACE AI investigation API.

A deliberately small app: the query routes for the configured read-only backends, backend
discovery, alert download, and health. It runs in its own container with no encryption capability
(see aceapi_ai.startup_checks, enforced by the entrypoint) -- nothing here may depend on decrypting
a secret.
"""

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from aceapi_ai.alerts.router import router as alerts_router
from aceapi_ai.health.router import router as health_router
from aceapi_ai.query.router import build_query_router
from saq.ai_query.registry import build_backend_registry
from saq.error.reporting import report_exception

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="ACE AI Investigation API",
        description="Read-only query endpoints for AI-driven alert investigation",
        version="1.0.0",
        root_path="/ai/v1",
    )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.error("unhandled exception processing %s %s", request.method, request.url.path)
        report_exception()
        return JSONResponse(status_code=500, content={"detail": "internal server error"})

    registry = build_backend_registry()
    app.state.backend_registry = registry

    app.include_router(build_query_router(registry), tags=["query"])
    app.include_router(alerts_router, prefix="/alerts", tags=["alerts"])
    app.include_router(health_router, prefix="/health", tags=["health"])

    return app


# Lazy module attribute (PEP 562): building the app reads the loaded configuration (the backend
# registry is config-driven), which does not exist yet when this module is imported at
# test-collection time. Access as aceapi_ai.application.app after environment initialization.
_app = None


def __getattr__(name: str) -> FastAPI:
    if name == "app":
        global _app
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
