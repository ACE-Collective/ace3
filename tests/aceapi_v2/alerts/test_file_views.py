"""GET /api/v2/alerts/{alert_uuid}/observables/{observable_uuid}/{text,hex,zip}: a file observable
of an alert as text, as a hex dump, or as an encrypted zip (the alert page's file actions)."""

import io
import logging
import os
import shutil
import subprocess
import uuid
import zipfile

import pytest
from httpx import AsyncClient

from aceapi_v2.alerts.service import hexdump
from saq.constants import F_TEST
from saq.database.util.alert import ALERT
from saq.environment import get_temp_dir
from tests.aceapi_v2.conftest import audit_actor_of, audit_record
from tests.saq.helpers import create_root_analysis

pytestmark = pytest.mark.integration

VIEWS = ("text", "hex", "zip")


def _path(alert_uuid: str, observable_uuid: str, view: str) -> str:
    return f"/alerts/{alert_uuid}/observables/{observable_uuid}/{view}"


def _alert_with_file(tmpdir, file_name: str, content: bytes):
    """An alert holding one file observable and one that is not a file; returns (alert uuid,
    file observable, other observable)."""
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    target_path = tmpdir / file_name
    target_path.write_binary(content)
    file_observable = root.add_file_observable(str(target_path))
    other = root.add_observable_by_spec(F_TEST, "not a file")
    root.save()
    ALERT(root)
    return root.uuid, file_observable, other


def _real_hexdump(content: bytes) -> str:
    return subprocess.run(["hexdump", "-C"], input=content, capture_output=True, check=True).stdout.decode()


class TestAccess:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("view", VIEWS)
    async def test_requires_auth(self, unauth_client: AsyncClient, view):
        assert (await unauth_client.get(_path(str(uuid.uuid4()), str(uuid.uuid4()), view))).status_code == 401

    @pytest.mark.asyncio
    @pytest.mark.parametrize("view", VIEWS)
    async def test_requires_alert_read(self, noperm_client: AsyncClient, view):
        assert (await noperm_client.get(_path(str(uuid.uuid4()), str(uuid.uuid4()), view))).status_code == 403

    @pytest.mark.asyncio
    @pytest.mark.parametrize("view", VIEWS)
    async def test_unknown_alert_or_file(self, client: AsyncClient, tmpdir, view):
        alert_uuid, file_observable, other = _alert_with_file(tmpdir, "sample.bin", b"data")

        assert (await client.get(_path(str(uuid.uuid4()), file_observable.uuid, view))).status_code == 404
        assert (await client.get(_path(alert_uuid, str(uuid.uuid4()), view))).status_code == 404
        # an observable that is not a file
        assert (await client.get(_path(alert_uuid, other.uuid, view))).status_code == 404

        os.remove(file_observable.full_path)
        assert (await client.get(_path(alert_uuid, file_observable.uuid, view))).status_code == 404


class TestText:
    @pytest.mark.asyncio
    async def test_the_bytes_as_text(self, client: AsyncClient, tmpdir, caplog: pytest.LogCaptureFixture):
        caplog.set_level(logging.INFO)
        alert_uuid, file_observable, _ = _alert_with_file(tmpdir, "notes.txt", "café\n".encode())

        response = await client.get(_path(alert_uuid, file_observable.uuid, "text"))

        assert response.status_code == 200
        assert response.headers["Content-Type"] == "text/plain; charset=utf-8"
        assert response.text == "café\n"
        assert f"AUDIT: user unittest viewed file {file_observable.uuid} of alert {alert_uuid} as text" in caplog.messages

    @pytest.mark.asyncio
    @pytest.mark.parametrize("view", ("text", "hex"))
    async def test_html_is_never_rendered(self, client: AsyncClient, tmpdir, view):
        """An alert's HTML or SVG opened in a tab must stay text on the GUI origin."""
        alert_uuid, file_observable, _ = _alert_with_file(
            tmpdir, "page.html", b"<html><body><script>alert(1)</script></body></html>")

        response = await client.get(_path(alert_uuid, file_observable.uuid, view))

        assert response.headers["Content-Type"] == "text/plain; charset=utf-8"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Content-Security-Policy"] == "sandbox"
        assert response.headers["Cache-Control"] == "private"
        assert "attachment" not in response.headers.get("Content-Disposition", "")


@pytest.mark.asyncio
@pytest.mark.parametrize("view, done", [("text", "viewed"), ("hex", "viewed"), ("zip", "downloaded")])
async def test_the_audit_record_names_the_key_that_acted(client: AsyncClient, client_actor, tmpdir,
                                                         caplog: pytest.LogCaptureFixture, view, done):
    caplog.set_level(logging.INFO)
    alert_uuid, file_observable, _ = _alert_with_file(tmpdir, "notes.txt", b"hello")

    assert (await client.get(_path(alert_uuid, file_observable.uuid, view))).status_code == 200

    audit = audit_record(caplog, f"user unittest {done} file {file_observable.uuid} of alert {alert_uuid}")
    assert (*audit_actor_of(audit), audit.alert_uuid, audit.observable_uuid) == (
        *client_actor, alert_uuid, file_observable.uuid)


class TestHex:
    @pytest.mark.asyncio
    async def test_a_hexdump_of_the_file(self, client: AsyncClient, tmpdir):
        content = b"#!/bin/sh\necho hello\n" + b"\x00" * 64 + bytes(range(256))
        alert_uuid, file_observable, _ = _alert_with_file(tmpdir, "script.sh", content)

        response = await client.get(_path(alert_uuid, file_observable.uuid, "hex"))

        assert response.status_code == 200
        assert response.text == _real_hexdump(content)

    @pytest.mark.skipif(shutil.which("hexdump") is None, reason="needs hexdump to compare with")
    @pytest.mark.parametrize("content", [
        b"",
        b"A",
        b"0123456789abcdef",
        b"0123456789abcdef0",
        b"\xff" * 48,
        b"\xff" * 48 + b"tail",
        b"x" * 16 + b"y" * 16 + b"x" * 16,
        b"\x00" * 15,
        bytes(range(256)) * 3,
    ])
    def test_the_format_is_hexdump_c(self, tmpdir, content):
        target = tmpdir / "content.bin"
        target.write_binary(content)

        assert "".join(hexdump(str(target))) == _real_hexdump(content)

    def test_it_is_sent_in_batches(self, tmpdir, monkeypatch):
        monkeypatch.setattr("aceapi_v2.alerts.service._HEXDUMP_BATCH_LINES", 2)
        target = tmpdir / "content.bin"
        target.write_binary(bytes(range(80)))

        batches = list(hexdump(str(target)))

        assert len(batches) == 3
        assert "".join(batches) == _real_hexdump(bytes(range(80)))


class TestZip:
    @pytest.mark.asyncio
    async def test_an_encrypted_zip_of_the_file(self, client: AsyncClient, tmpdir, caplog: pytest.LogCaptureFixture):
        caplog.set_level(logging.INFO)
        alert_uuid, file_observable, _ = _alert_with_file(tmpdir, "invoice.exe", b"MZ not really a program")
        before = set(os.listdir(get_temp_dir()))

        response = await client.get(_path(alert_uuid, file_observable.uuid, "zip"))

        assert response.status_code == 200
        assert response.headers["Content-Type"] == "application/zip"
        assert response.headers["Content-Disposition"] == 'attachment; filename="invoice.exe.zip"'
        archive = zipfile.ZipFile(io.BytesIO(response.content))
        assert archive.namelist() == ["invoice.exe"]
        with pytest.raises(RuntimeError):
            archive.read("invoice.exe")
        assert archive.read("invoice.exe", pwd=b"infected") == b"MZ not really a program"
        assert f"AUDIT: user unittest downloaded file {file_observable.uuid} of alert {alert_uuid}" in caplog.messages
        # the zip is removed once it has been sent
        assert set(os.listdir(get_temp_dir())) == before

    @pytest.mark.asyncio
    async def test_the_download_name_is_a_plain_file_name(self, client: AsyncClient, tmpdir):
        alert_uuid, file_observable, _ = _alert_with_file(tmpdir, 'bad"name; x=1.js', b"var a;")

        response = await client.get(_path(alert_uuid, file_observable.uuid, "zip"))

        assert response.headers["Content-Disposition"] == 'attachment; filename="bad_name_x_1.js.zip"'
