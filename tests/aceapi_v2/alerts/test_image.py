"""GET /api/v2/alerts/{alert_uuid}/observables/{observable_uuid}/image: an image file from an
alert, for the <img> tags on the alert and event pages."""

import os
import uuid

import pytest
from httpx import AsyncClient

from saq.analysis.root import RootAnalysis
from saq.constants import F_TEST
from saq.database.model import Alert
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from tests.saq.helpers import create_root_analysis

pytestmark = pytest.mark.integration

# a single pixel PNG image (1x1 transparent pixel)
PNG_DATA = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01' \
           b'\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\xdac\xf8\x0f' \
           b'\x00\x01\x01\x01\x00\x18\xdd\x8d\x18\x00\x00\x00\x00IEND\xaeB`\x82'

JPEG_DATA = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb'


def _image_path(alert_uuid: str, observable_uuid: str) -> str:
    return f"/alerts/{alert_uuid}/observables/{observable_uuid}/image"


def _alert_with_file(tmpdir, file_name: str, content, mime_type_known: bool = True):
    """An alert holding one file observable; returns (alert uuid, observable)."""
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    target_path = tmpdir / file_name
    if isinstance(content, bytes):
        target_path.write_binary(content)
    else:
        target_path.write_text(content, encoding="utf8")

    file_observable = root.add_file_observable(str(target_path))
    if not mime_type_known:
        # alerts analyzed before the observable carried its own mime type
        file_observable.mime_type = None
    root.save()
    ALERT(root)
    return root.uuid, file_observable


@pytest.mark.asyncio
async def test_requires_auth(unauth_client: AsyncClient):
    response = await unauth_client.get(_image_path(str(uuid.uuid4()), str(uuid.uuid4())))
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_requires_alert_read(noperm_client: AsyncClient):
    response = await noperm_client.get(_image_path(str(uuid.uuid4()), str(uuid.uuid4())))
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_invalid_alert_uuid(client: AsyncClient):
    assert (await client.get(_image_path("not-a-uuid", str(uuid.uuid4())))).status_code == 400


@pytest.mark.asyncio
async def test_unknown_alert(client: AsyncClient):
    assert (await client.get(_image_path(str(uuid.uuid4()), str(uuid.uuid4())))).status_code == 404


@pytest.mark.asyncio
async def test_png(client: AsyncClient, tmpdir):
    alert_uuid, file_observable = _alert_with_file(tmpdir, "test.png", PNG_DATA)
    assert file_observable.mime_type == "image/png"

    response = await client.get(_image_path(alert_uuid, file_observable.uuid))

    assert response.status_code == 200
    assert response.headers["Content-Type"] == "image/png"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Content-Security-Policy"] == "sandbox"
    assert response.headers["Cache-Control"] == "private"
    assert response.content == PNG_DATA


@pytest.mark.asyncio
async def test_jpeg(client: AsyncClient, tmpdir):
    alert_uuid, file_observable = _alert_with_file(tmpdir, "test.jpg", JPEG_DATA)
    assert file_observable.mime_type == "image/jpeg"

    response = await client.get(_image_path(alert_uuid, file_observable.uuid))

    assert response.status_code == 200
    assert response.headers["Content-Type"] == "image/jpeg"
    assert response.content == JPEG_DATA


@pytest.mark.asyncio
async def test_alert_without_a_stored_mime_type(client: AsyncClient, tmpdir):
    alert_uuid, file_observable = _alert_with_file(tmpdir, "test.png", PNG_DATA, mime_type_known=False)

    response = await client.get(_image_path(alert_uuid, file_observable.uuid))

    assert response.status_code == 200
    assert response.headers["Content-Type"] == "image/png"
    assert response.content == PNG_DATA


@pytest.mark.asyncio
async def test_does_not_load_the_analysis_tree(client: AsyncClient, tmpdir, monkeypatch):
    """An alert page fetches one of these per image it shows; building the whole tree for each
    re-parsed data.json and rehydrated every observable and analysis in the alert."""
    alert_uuid, file_observable = _alert_with_file(tmpdir, "test.png", PNG_DATA)

    def _no_load(self, *args, **kwargs):
        raise AssertionError("the image endpoint built the full analysis tree")

    monkeypatch.setattr(RootAnalysis, "load", _no_load)

    response = await client.get(_image_path(alert_uuid, file_observable.uuid))

    assert response.status_code == 200
    assert response.content == PNG_DATA


@pytest.mark.asyncio
async def test_unknown_observable(client: AsyncClient, tmpdir):
    alert_uuid, _ = _alert_with_file(tmpdir, "test.png", PNG_DATA)

    response = await client.get(_image_path(alert_uuid, str(uuid.uuid4())))

    assert response.status_code == 404
    assert response.json()["detail"] == "unknown file"


@pytest.mark.asyncio
async def test_missing_file(client: AsyncClient, tmpdir):
    alert_uuid, file_observable = _alert_with_file(tmpdir, "test.png", PNG_DATA)
    os.unlink(file_observable.full_path)

    response = await client.get(_image_path(alert_uuid, file_observable.uuid))

    assert response.status_code == 404
    assert response.json()["detail"] == "unknown file"


@pytest.mark.asyncio
async def test_observable_that_is_not_a_file(client: AsyncClient):
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    observable = root.add_observable_by_spec(F_TEST, "not_a_file")
    root.save()
    ALERT(root)

    response = await client.get(_image_path(root.uuid, observable.uuid))

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_archived_alert(client: AsyncClient, tmpdir):
    alert_uuid, file_observable = _alert_with_file(tmpdir, "test.png", PNG_DATA)
    db = get_db()
    db.execute(Alert.__table__.update().where(Alert.uuid == alert_uuid).values(archived=True))
    db.commit()

    response = await client.get(_image_path(alert_uuid, file_observable.uuid))

    assert response.status_code == 410


#
# The URL of an image can be opened as a page, so a file from an alert must never come back from
# it as something the browser renders as a document on the GUI origin.
#


@pytest.mark.asyncio
async def test_rejects_a_file_that_is_not_an_image(client: AsyncClient, tmpdir):
    alert_uuid, file_observable = _alert_with_file(
        tmpdir, "page.html", "<html><body><script>alert(1)</script></body></html>")
    assert file_observable.mime_type == "text/html"

    response = await client.get(_image_path(alert_uuid, file_observable.uuid))

    assert response.status_code == 404
    assert b"<script>" not in response.content


@pytest.mark.asyncio
async def test_serves_svg_sandboxed(client: AsyncClient, tmpdir):
    """An SVG is an image and is served, but opened as a page it could run scripts: the sandbox
    policy is what stops them."""
    alert_uuid, file_observable = _alert_with_file(
        tmpdir, "image.svg",
        '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><script>alert(1)</script></svg>')
    assert file_observable.mime_type == "image/svg+xml"

    response = await client.get(_image_path(alert_uuid, file_observable.uuid))

    assert response.status_code == 200
    assert response.headers["Content-Type"] == "image/svg+xml"
    assert response.headers["Content-Security-Policy"] == "sandbox"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
