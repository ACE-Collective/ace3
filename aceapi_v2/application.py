"""FastAPI application factory for ACE API v2."""

from fastapi import FastAPI

from aceapi_v2.auth.router import router as auth_router
from aceapi_v2.health.router import router as health_router
from aceapi_v2.observable_types.router import router as observable_types_router
from aceapi_v2.threat_types.router import router as threat_types_router
from aceapi_v2.threats.router import router as threats_router


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="ACE API v2",
        description="Analysis Correlation Engine API v2",
        version="2.0.0",
        root_path="/api/v2",
    )

    # Include routers
    app.include_router(auth_router, prefix="/auth", tags=["authentication"])
    app.include_router(health_router, prefix="/health", tags=["health"])
    app.include_router(observable_types_router, prefix="/observable-types", tags=["observables"])
    app.include_router(threat_types_router, prefix="/threat-types", tags=["threats"])
    app.include_router(threats_router, prefix="/threats", tags=["threats"])

    return app


# Create app instance for imports (used by tests)
app = create_app()
