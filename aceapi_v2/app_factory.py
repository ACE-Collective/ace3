"""What both FastAPI applications of API v2 are built on, and the node-to-node one.

The http-api-engine container imports create_engine_app() from here rather than from aceapi_v2.application, which
imports every router of the API: its workers serve only the engine, health and common routes (docs/ENGINE_API.md).
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from aceapi_v2.common.router import router as common_router
from aceapi_v2.engine.router import router as engine_router
from aceapi_v2.health.router import router as health_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: the shutdown half is the part that matters."""
    yield

    logger.info("shutting down api")

    from aceapi_v2.database import dispose_engines_for_current_loop
    from aceapi_v2.sync import shutdown_loop

    try:
        await dispose_engines_for_current_loop()
    except Exception as e:
        logger.debug("error disposing async engines: %s", e)

    try:
        shutdown_loop()
    except Exception as e:
        logger.debug("error stopping the background event loop: %s", e)


def new_app(title: str, description: str) -> FastAPI:
    """A FastAPI application under /api/v2 with the shared lifespan and exception handler."""
    app = FastAPI(
        title=title,
        description=description,
        version="2.0.0",
        root_path="/api/v2",
        lifespan=lifespan,
    )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.error("unhandled exception processing %s %s", request.method, request.url.path, exc_info=exc)
        return JSONResponse(status_code=500, content={"detail": "internal server error"})

    return app


def create_engine_app() -> FastAPI:
    """Create the node-to-node application served by the http-api-engine container.

    nginx routes /api/v2/engine/ to that container so that engine traffic never competes with
    user traffic for the workers of http-api-v2 (see docs/ENGINE_API.md). It mounts nothing a
    user would call."""
    app = new_app("ACE API v2 (engine)", "Analysis Correlation Engine API v2: node-to-node routes")
    app.include_router(engine_router, prefix="/engine", tags=["engine"])
    app.include_router(health_router, prefix="/health", tags=["health"])
    app.include_router(common_router, prefix="/common", tags=["common"])
    return app
