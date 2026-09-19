"""Response classes that publish their media type in the generated OpenAPI schema.

FastAPI takes the documented content type of a route's success response from
``route.response_class.media_type`` and from nothing else (``fastapi/openapi/utils.py``).
The ``-> FileResponse`` return annotation only tells it "do not build a response model for
this", and the ``media_type=`` passed to the response *instance* is read far too late to
reach schema generation. A route that serves a zip while leaving ``response_class`` at its
default therefore publishes ``application/json``, and a generated client calls
``response.json()`` on the bytes. Passing one of these classes as ``response_class=`` is
what fixes the published schema.

Three things to know before changing any of this:

* Adding a ``responses={200: {"content": {...}}}`` block *instead of* ``response_class=``
  does not work. FastAPI deep-merges ``route.responses`` onto the entry it already built,
  so ``application/json`` survives alongside the new type -- and it stays first, which is
  what a generator keys off. ``ZIP_DOWNLOAD_RESPONSES`` below is keyed off
  ``ZipFileResponse.media_type`` so the two levers can never drift apart and reintroduce a
  two-content-type operation.

* starlette's ``FileResponse.__init__`` ignores the class-level ``media_type``: when the
  argument is None it guesses from the filename instead (``application/octet-stream`` for
  a saq.log). The ``FileResponse`` call sites must keep passing ``media_type=`` explicitly
  -- the class attribute here reaches the schema only. ``Response.__init__``, and so
  ``PlainTextResponse``, does honor it.

* Never give these classes an ``__init__`` without a ``status_code`` parameter. FastAPI
  reads the documented success status code out of
  ``inspect.signature(response_class.__init__)`` and raises ``UnboundLocalError`` when that
  parameter is missing. Plain subclasses with no ``__init__`` are the correct shape.
"""

from fastapi.responses import FileResponse, PlainTextResponse


class ZipFileResponse(FileResponse):
    """A file served as an application/zip download (the encrypted alert and crash archives)."""

    media_type = "application/zip"


class TextFileResponse(FileResponse):
    """A file served as text/plain (an alert's saq.log)."""

    media_type = "text/plain"


class CsvResponse(PlainTextResponse):
    """Generated CSV text (the event export)."""

    media_type = "text/csv"


# Describes the body of the zip download endpoints for generators that look at the schema
# rather than only at the content type. FastAPI merges this into the operation without
# mutating or aliasing it, so one shared dict across routes is safe.
ZIP_DOWNLOAD_RESPONSES = {
    200: {
        "content": {
            ZipFileResponse.media_type: {
                "schema": {"type": "string", "contentMediaType": ZipFileResponse.media_type}
            }
        }
    }
}
