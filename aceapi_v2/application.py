"""FastAPI application factory for ACE API v2."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Security
from fastapi.responses import JSONResponse

from aceapi_v2.alerts.router import router as alerts_router
from aceapi_v2.analysis.router import router as analysis_router
from aceapi_v2.cli.router import router as cli_router
from aceapi_v2.common.router import router as common_router
from aceapi_v2.crashes.router import router as crashes_router
from aceapi_v2.dependencies import get_current_auth
from aceapi_v2.detection.router import router as detection_router
from aceapi_v2.detection_points.router import router as detection_points_router
from aceapi_v2.email.router import router as email_router
from aceapi_v2.engine.router import router as engine_router
from aceapi_v2.events.router import router as events_router
from aceapi_v2.file_collection.router import router as file_collection_router
from aceapi_v2.filter_screens.router import router as filter_screens_router
from aceapi_v2.health.router import router as health_router
from aceapi_v2.hunt.router import router as hunt_router
from aceapi_v2.integrations import router as integrations_router
from aceapi_v2.nodes.router import router as nodes_router
from aceapi_v2.observable_types.router import router as observable_types_router
from aceapi_v2.observables.router import router as observables_router
from aceapi_v2.remediation.router import router as remediation_router
from aceapi_v2.saved_filters.router import router as saved_filters_router
from aceapi_v2.search.router import router as search_router
from aceapi_v2.secrets.router import router as secrets_router
from aceapi_v2.svs.alerts.router import router as svs_alerts_router
from aceapi_v2.svs.catalog.router import router as svs_tests_router
from aceapi_v2.svs.coverage.router import router as svs_coverage_router
from aceapi_v2.svs.expectations.router import router as svs_expectations_router
from aceapi_v2.svs.ignores.router import router as svs_ignores_router
from aceapi_v2.svs.runs.router import router as svs_runs_router
from aceapi_v2.svs.samples.router import router as svs_samples_router
from aceapi_v2.svs.test_hosts.router import router as svs_test_hosts_router
from aceapi_v2.svs.worklist.router import router as svs_worklist_router
from aceapi_v2.svs.yara.validations.router import router as svs_validations_router
from aceapi_v2.threat_types.router import router as threat_types_router
from aceapi_v2.observable_comments.router import router as observable_comments_router
from aceapi_v2.threats.router import router as threats_router
from aceapi_v2.user_preferences.router import router as user_preferences_router
from aceapi_v2.users.router import router as users_router
from aceapi_v2.yara_qa.router import router as yara_qa_router
from saq.error.reporting import report_exception

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


def _new_app(title: str, description: str) -> FastAPI:
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
        logger.error("unhandled exception processing %s %s", request.method, request.url.path)
        report_exception()
        return JSONResponse(status_code=500, content={"detail": "internal server error"})

    return app


def create_engine_app() -> FastAPI:
    """Create the node-to-node application served by the http-api-engine container.

    nginx routes /api/v2/engine/ to that container so that engine traffic never competes with
    user traffic for the workers of http-api-v2 (see docs/ENGINE_API.md). It mounts nothing a
    user would call."""
    app = _new_app("ACE API v2 (engine)", "Analysis Correlation Engine API v2: node-to-node routes")
    app.include_router(engine_router, prefix="/engine", tags=["engine"])
    app.include_router(health_router, prefix="/health", tags=["health"])
    app.include_router(common_router, prefix="/common", tags=["common"])
    return app


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = _new_app("ACE API v2", "Analysis Correlation Engine API v2")

    # Include routers. The engine routes are mounted here too, so this app stays complete (tests,
    # ace gui start --api-v2); in the container deployment nginx sends /api/v2/engine/ to
    # create_engine_app() instead.
    app.include_router(alerts_router, prefix="/alerts", tags=["alerts"])
    # one alert's side of SVS: /alerts/{uuid}/svs
    app.include_router(svs_alerts_router, prefix="/alerts", tags=["svs"])
    app.include_router(analysis_router, prefix="/analysis", tags=["analysis"])
    app.include_router(cli_router, prefix="/cli", tags=["cli"])
    app.include_router(common_router, prefix="/common", tags=["common"])
    app.include_router(crashes_router, prefix="/crashes", tags=["crashes"])
    app.include_router(detection_router, prefix="/detection", tags=["detection"])
    app.include_router(detection_points_router, prefix="/detection-points", tags=["detection-points"])
    app.include_router(email_router, prefix="/email", tags=["email"])
    app.include_router(engine_router, prefix="/engine", tags=["engine"])
    app.include_router(events_router, prefix="/events", tags=["events"])
    app.include_router(file_collection_router, prefix="/file-collections", tags=["file-collections"])
    app.include_router(filter_screens_router, prefix="/filter-screens", tags=["saved-filters"])
    app.include_router(health_router, prefix="/health", tags=["health"])
    app.include_router(hunt_router, prefix="/hunt", tags=["hunt"])
    app.include_router(nodes_router, prefix="/nodes", tags=["nodes"])
    app.include_router(observable_comments_router, prefix="/observable-comments", tags=["observables"])
    app.include_router(observable_types_router, prefix="/observable-types", tags=["observables"])
    app.include_router(observables_router, prefix="/observables", tags=["observables"])
    app.include_router(remediation_router, prefix="/remediation", tags=["remediation"])
    app.include_router(saved_filters_router, prefix="/saved-filters", tags=["saved-filters"])
    app.include_router(search_router, prefix="/search", tags=["search"])
    app.include_router(secrets_router, prefix="/secrets", tags=["secrets"])
    app.include_router(svs_samples_router, prefix="/svs/samples", tags=["svs"])
    app.include_router(svs_validations_router, prefix="/svs/yara/validations", tags=["svs"])
    app.include_router(svs_test_hosts_router, prefix="/svs/test-hosts", tags=["svs"])
    app.include_router(svs_tests_router, prefix="/svs/tests", tags=["svs"])
    app.include_router(svs_expectations_router, prefix="/svs/expectations", tags=["svs"])
    app.include_router(svs_ignores_router, prefix="/svs/ignores", tags=["svs"])
    app.include_router(svs_runs_router, prefix="/svs/runs", tags=["svs"])
    app.include_router(svs_coverage_router, prefix="/svs/coverage", tags=["svs"])
    app.include_router(svs_worklist_router, prefix="/svs/worklist", tags=["svs"])
    app.include_router(yara_qa_router, prefix="/signatures/yara-qa", tags=["signatures"])
    app.include_router(threat_types_router, prefix="/threat-types", tags=["threats"])
    app.include_router(threats_router, prefix="/threats", tags=["threats"])
    app.include_router(users_router, prefix="/users", tags=["users"])
    # mounted under /users/me so the URL says whose preferences these are; the router itself
    # takes the user from the auth result
    app.include_router(user_preferences_router, prefix="/users/me/preferences", tags=["users"])

    # the routes of integrations, under /integrations/<name> so they never collide with these
    app.include_router(integrations_router, prefix="/integrations", tags=["integrations"],
                       dependencies=[Security(get_current_auth)])

    return app


# Create app instance for imports (used by tests)
app = create_app()
