"""FastAPI application factory for ACE API v2."""

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from aceapi_v2.alerts.router import router as alerts_router
from aceapi_v2.auth.router import router as auth_router
from aceapi_v2.common.router import router as common_router
from aceapi_v2.detection.router import router as detection_router
from aceapi_v2.events.router import router as events_router
from aceapi_v2.health.router import router as health_router
from aceapi_v2.nodes.router import router as nodes_router
from aceapi_v2.observable_types.router import router as observable_types_router
from aceapi_v2.observables.router import router as observables_router
from aceapi_v2.threat_types.router import router as threat_types_router
from aceapi_v2.observable_comments.router import router as observable_comments_router
from aceapi_v2.threats.router import router as threats_router
from aceapi_v2.users.router import router as users_router
from saq.error.reporting import report_exception

logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="ACE API v2",
        description="Analysis Correlation Engine API v2",
        version="2.0.0",
        root_path="/api/v2",
    )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.error("unhandled exception processing %s %s", request.method, request.url.path)
        report_exception()
        return JSONResponse(status_code=500, content={"detail": "internal server error"})

    # Include routers
    app.include_router(alerts_router, prefix="/alerts", tags=["alerts"])
    app.include_router(auth_router, prefix="/auth", tags=["authentication"])
    app.include_router(common_router, prefix="/common", tags=["common"])
    app.include_router(detection_router, prefix="/detection", tags=["detection"])
    app.include_router(events_router, prefix="/events", tags=["events"])
    app.include_router(health_router, prefix="/health", tags=["health"])
    app.include_router(nodes_router, prefix="/nodes", tags=["nodes"])
    app.include_router(observable_comments_router, prefix="/observable-comments", tags=["observables"])
    app.include_router(observable_types_router, prefix="/observable-types", tags=["observables"])
    app.include_router(observables_router, prefix="/observables", tags=["observables"])
    app.include_router(threat_types_router, prefix="/threat-types", tags=["threats"])
    app.include_router(threats_router, prefix="/threats", tags=["threats"])
    app.include_router(users_router, prefix="/users", tags=["users"])

    return app


# Create app instance for imports (used by tests)
app = create_app()
