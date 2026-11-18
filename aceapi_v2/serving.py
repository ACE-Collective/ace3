"""The ASGI application uvicorn serves for one of the API apps.

nginx forwards a request with its prefix (/api/v2/alerts/...) and the apps route without it, so the app is mounted
under the prefix. FastAPI's root_path parameter did this before FastAPI deprecated it, and uvicorn's --root-path
cannot replace it: it prepends the prefix to a path that already has it.
"""

from fastapi import FastAPI
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.types import ASGIApp, Receive, Scope, Send


def serve_under(prefix: str, app: FastAPI) -> ASGIApp:
    mounted = Starlette(routes=[Mount(prefix, app=app)])

    async def application(scope: Scope, receive: Receive, send: Send) -> None:
        # a mounted app's lifespan never runs, and the API's lifespan disposes the async engines at shutdown
        if scope["type"] == "lifespan":
            await app(scope, receive, send)
        else:
            await mounted(scope, receive, send)

    return application
