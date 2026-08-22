"""Query routes for the AI investigation API.

One POST route per enabled backend, each gated on its own ai:<name> permission -- the route set is
config-driven, so a deployment that enables a backend gets its route and its permission gate in one
step. Discovery is GET /backends.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Security
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_ai.dependencies import get_current_auth
from aceapi_ai.query import service
from aceapi_ai.query.schemas import (
    AIQueryRequestBody,
    AIQueryResponse,
    BackendDescriptor,
)
from aceapi_v2.auth.schemas import ApiAuthResult
from aceapi_v2.database import get_async_session
from aceapi_v2.dependencies import require_permission
from saq.ai_query.interface import AIQueryBackend


def _register_query_route(router: APIRouter, backend: AIQueryBackend) -> None:
    permission = require_permission("ai", backend.name, auth_dependency=get_current_auth)

    @router.post(f"/query/{backend.name}", response_model=AIQueryResponse, name=f"query_{backend.name}")
    async def query_backend(
        body: AIQueryRequestBody,
        request: Request,
        auth: Annotated[ApiAuthResult, Depends(permission)],
    ) -> AIQueryResponse:
        return await service.execute_query(backend, body, auth, request)

    query_backend.__doc__ = f"Run a read-only {backend.name} query."


def build_query_router(registry: dict[str, AIQueryBackend]) -> APIRouter:
    router = APIRouter()

    for name in sorted(registry):
        _register_query_route(router, registry[name])

    @router.get("/backends", response_model=list[BackendDescriptor])
    async def list_backends(
        auth: Annotated[ApiAuthResult, Security(get_current_auth)],
        session: Annotated[AsyncSession, Depends(get_async_session)],
    ) -> list[BackendDescriptor]:
        """Describe the enabled backends and whether the caller's credential reaches each one."""
        return await service.describe_backends(registry, auth, session)

    return router
