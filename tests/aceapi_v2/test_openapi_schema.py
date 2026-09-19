"""The published OpenAPI schema must agree with what the routes actually put on the wire.

FastAPI documents a route's success content type from ``route.response_class.media_type`` and
from nothing else -- not the ``-> FileResponse`` annotation, and not the ``media_type=`` passed
to the response instance. A route that serves a zip or a log file while leaving
``response_class`` at its default is published as ``application/json``, and a client generated
from that schema calls ``response.json()`` on the bytes and raises JSONDecodeError.

Every other test of these endpoints asserts on the real HTTP response, which was always correct,
so nothing caught that. These do, by reading the generated document directly.

See aceapi_v2/responses.py for the response classes that make this come out right.
"""

import pytest

# path -> the one media type its 200 response may advertise
V2_BINARY_ROUTES = {
    "/alerts/{alert_uuid}/download": "application/zip",
    "/alerts/{alert_uuid}/logs": "text/plain",
    "/crashes/{crash_id}/download": "application/zip",
    "/events/export": "text/csv",
}

AI_BINARY_ROUTES = {
    "/alerts/{alert_uuid}/download": "application/zip",
    "/alerts/{alert_uuid}/logs": "text/plain",
}


def _content_types(schema: dict, path: str) -> set[str]:
    """The media types the schema advertises for GET <path>'s 200 response.

    Paths are the bare route paths; the schema does not carry the app's root_path
    (/api/v2, /ai/v1).
    """
    return set(schema["paths"][path]["get"]["responses"]["200"]["content"])


@pytest.mark.unit
class TestBinaryResponseMediaTypes:
    """Routes that serve a file or text publish that media type, and only that one.

    Asserting the exact set rather than merely "not application/json" is deliberate: a
    ``responses=`` block whose key drifts away from the response class's media_type would
    publish two content types, and a generator picks the first one it recognises. That is
    the exact shape of the original defect.
    """

    @pytest.mark.parametrize("path,media_type", sorted(V2_BINARY_ROUTES.items()))
    def test_aceapi_v2_route_advertises_its_media_type(self, path, media_type):
        from aceapi_v2.application import app

        assert _content_types(app.openapi(), path) == {media_type}

    @pytest.mark.parametrize("path,media_type", sorted(AI_BINARY_ROUTES.items()))
    def test_aceapi_ai_route_advertises_its_media_type(self, path, media_type):
        # imported lazily: the AI app builds its backend registry from the loaded configuration
        import aceapi_ai.application

        assert _content_types(aceapi_ai.application.app.openapi(), path) == {media_type}
