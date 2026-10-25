"""FastAPI application factory for ACE API v2."""

from fastapi import FastAPI, Security

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
from aceapi_v2.app_factory import new_app
from aceapi_v2.events.router import router as events_router
from aceapi_v2.file_collection.router import router as file_collection_router
from aceapi_v2.filter_screens.router import router as filter_screens_router
from aceapi_v2.health.router import router as health_router
from aceapi_v2.hunt.router import router as hunt_router
from aceapi_v2.integrations import get_integrations_router
from aceapi_v2.nodes.router import router as nodes_router
from aceapi_v2.observable_types.router import router as observable_types_router
from aceapi_v2.observables.router import router as observables_router
from aceapi_v2.remediation.router import router as remediation_router
from aceapi_v2.saved_filters.router import router as saved_filters_router
from aceapi_v2.search.router import router as search_router
from aceapi_v2.secrets.router import router as secrets_router
from aceapi_v2.svs.alerts.router import router as svs_alerts_router
from aceapi_v2.svs.catalog.router import repositories_router as svs_catalog_repositories_router
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

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = new_app("ACE API v2", "Analysis Correlation Engine API v2")

    # Include routers. The engine routes are mounted here too, so this app stays complete (tests,
    # ace gui start --api-v2); in the container deployment nginx sends /api/v2/engine/ to
    # aceapi_v2.app_factory.create_engine_app() instead.
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
    app.include_router(svs_catalog_repositories_router, prefix="/svs/catalog", tags=["svs"])
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
    app.include_router(get_integrations_router(), prefix="/integrations", tags=["integrations"],
                       dependencies=[Security(get_current_auth)])

    return app


# The tests import an app instance as aceapi_v2.application.app. It is built on first access (PEP 562), not when
# this module is imported: the API entry points import it to call create_app() themselves, and building it here
# built a second application in every API worker.
_app = None


def __getattr__(name: str) -> FastAPI:
    if name == "app":
        global _app
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
