"""/api/v2/engine: moving a work target between nodes (download, upload, clear)."""

import io
import json
import os
import shutil
import tarfile
import uuid

import pytest
from httpx import AsyncClient

from saq.analysis.root import RootAnalysis
from saq.constants import ANALYSIS_MODE_ANALYSIS, ANALYSIS_MODE_CORRELATION
from saq.database.model import Alert
from saq.database.pool import get_db, get_db_connection
from saq.database.util.alert import ALERT
from saq.database.util.locking import acquire_lock
from saq.environment import get_global_runtime_settings, get_temp_dir
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import create_root_analysis

pytestmark = pytest.mark.integration


def _root_with_a_file(storage_dir: str | None = None, analysis_mode: str | None = None) -> tuple[RootAnalysis, str]:
    root = create_root_analysis(uuid=str(uuid.uuid4()), storage_dir=storage_dir, analysis_mode=analysis_mode)
    root.initialize_storage()
    root.details = {"hello": "world"}
    with open(root.create_file_path("test.dat"), "w") as fp:
        fp.write("test")
    file_observable = root.add_file_observable(root.create_file_path("test.dat"))
    root.save()
    return root, file_observable.uuid


def _uploadable(analysis_mode: str | None = None) -> RootAnalysis:
    """A root outside this node's storage, as another node would hold it."""
    root, _ = _root_with_a_file(os.path.join(get_temp_dir(), f"test_upload_{uuid.uuid4()}"), analysis_mode)
    return root


def _tar(directory: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        tar.add(directory, ".")
    return buffer.getvalue()


async def _upload(client: AsyncClient, root: RootAnalysis, **modifiers):
    return await client.post(
        f"/engine/upload/{root.uuid}",
        data={"upload_modifiers": json.dumps(modifiers)},
        files={"archive": ("upload.tar", _tar(root.storage_dir), "application/x-tar")})


def _alert_rows(alert_uuid: str) -> list[Alert]:
    get_db().close()
    return get_db().query(Alert).filter(Alert.uuid == alert_uuid).all()


class TestDownload:
    @pytest.mark.asyncio
    async def test_the_storage_directory_as_a_tar(self, client: AsyncClient):
        root, file_uuid = _root_with_a_file()

        response = await client.get(f"/engine/download/{root.uuid}")

        assert response.status_code == 200
        assert response.headers["Content-Type"] == "application/x-tar"
        output_dir = os.path.join(get_temp_dir(), f"download_{uuid.uuid4()}")
        try:
            with tarfile.open(fileobj=io.BytesIO(response.content), mode="r|") as tar:
                tar.extractall(path=output_dir, filter="data")

            downloaded = RootAnalysis(storage_dir=output_dir)
            downloaded.load()
            downloaded.load_details()
            assert downloaded.details == {"hello": "world"}
            with open(downloaded.get_observable(file_uuid).full_path) as fp:
                assert fp.read() == "test"
        finally:
            shutil.rmtree(output_dir, ignore_errors=True)

        # the tar is removed once it has been sent
        assert not [name for name in os.listdir(get_temp_dir()) if name.startswith(f"download_{root.uuid}")]

    @pytest.mark.asyncio
    async def test_unknown_target(self, client: AsyncClient):
        assert (await client.get(f"/engine/download/{uuid.uuid4()}")).status_code == 404
        assert (await client.get("/engine/download/not-a-uuid")).status_code == 400


class TestUpload:
    @pytest.mark.asyncio
    async def test_extracts_into_this_nodes_storage(self, client: AsyncClient):
        root = _uploadable()

        response = await _upload(client, root, overwrite=False, sync=True)

        assert response.status_code == 200
        assert response.json() == {"result": True, "storage_dir": get_storage_dir(root.uuid)}
        uploaded = RootAnalysis(storage_dir=get_storage_dir(root.uuid))
        uploaded.load()
        uploaded.load_details()
        assert uploaded.details == {"hello": "world"}
        assert uploaded.location == get_global_runtime_settings().saq_node
        # sync schedules it
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT COUNT(*) FROM workload WHERE uuid = %s", (root.uuid,))
            assert cursor.fetchone()[0] == 1

    @pytest.mark.asyncio
    async def test_move_repoints_the_alert(self, client: AsyncClient):
        root = _uploadable()
        ALERT(root)
        alert = get_db().query(Alert).filter(Alert.uuid == root.uuid).one()
        alert.load()
        alert.location = "some node"
        alert.sync()

        response = await _upload(client, root, overwrite=False, sync=False, move=True)

        assert response.status_code == 200
        (alert,) = _alert_rows(root.uuid)
        assert alert.storage_dir == get_storage_dir(root.uuid) != root.storage_dir
        assert alert.location == get_global_runtime_settings().saq_node

    @pytest.mark.asyncio
    async def test_a_correlation_root_gets_its_alert(self, client: AsyncClient):
        """What RemoteNode.submit_remote sends (is_alert=False, sync=True): a correlation-mode root
        is an alert, so the receiving node inserts its row, as submit_local does."""
        root = _uploadable(ANALYSIS_MODE_CORRELATION)

        response = await _upload(client, root, overwrite=False, sync=True, move=False, is_alert=False)

        assert response.status_code == 200
        (alert,) = _alert_rows(root.uuid)
        assert alert.storage_dir == response.json()["storage_dir"] == get_storage_dir(root.uuid)
        assert alert.description == root.description

    @pytest.mark.asyncio
    async def test_an_analysis_root_gets_no_alert(self, client: AsyncClient):
        root = _uploadable(ANALYSIS_MODE_ANALYSIS)

        response = await _upload(client, root, overwrite=False, sync=True, move=False, is_alert=False)

        assert response.status_code == 200
        assert _alert_rows(root.uuid) == []

    @pytest.mark.asyncio
    async def test_a_move_of_an_existing_alert_does_not_duplicate_it(self, client: AsyncClient):
        """A move or a drain carries an alert that already has its row; the row is repointed, never
        inserted again."""
        root = _uploadable(ANALYSIS_MODE_CORRELATION)
        ALERT(root)

        response = await _upload(client, root, overwrite=False, sync=False, move=True, is_alert=True)

        assert response.status_code == 200
        (alert,) = _alert_rows(root.uuid)
        assert alert.storage_dir == get_storage_dir(root.uuid)

    @pytest.mark.asyncio
    async def test_an_existing_target_needs_overwrite(self, client: AsyncClient):
        root = _uploadable()
        assert (await _upload(client, root, sync=False)).status_code == 200

        assert (await _upload(client, root, sync=False)).status_code == 409
        assert (await _upload(client, root, overwrite=True, sync=False)).status_code == 200

    @pytest.mark.asyncio
    @pytest.mark.parametrize("modifiers", ['{"sync": "yes"}', '{"colour": true}', "not json"])
    async def test_bad_modifiers(self, client: AsyncClient, modifiers):
        root = _uploadable()
        response = await client.post(
            f"/engine/upload/{root.uuid}", data={"upload_modifiers": modifiers},
            files={"archive": ("upload.tar", _tar(root.storage_dir), "application/x-tar")})

        assert response.status_code == 422
        assert not os.path.exists(get_storage_dir(root.uuid))

    @pytest.mark.asyncio
    async def test_a_link_out_of_the_directory_is_refused(self, client: AsyncClient):
        """The archive is extracted with the data filter: it cannot write outside the storage
        directory."""
        root = _uploadable()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            link = tarfile.TarInfo("escape")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tar.addfile(link)

        response = await client.post(f"/engine/upload/{root.uuid}", data={"upload_modifiers": "{}"},
                                     files={"archive": ("upload.tar", buffer.getvalue(), "application/x-tar")})

        assert response.status_code == 400
        assert "invalid archive" in response.json()["detail"]
        assert not os.path.exists(get_storage_dir(root.uuid))

    @pytest.mark.asyncio
    async def test_not_a_tar(self, client: AsyncClient):
        root = _uploadable()
        response = await client.post(f"/engine/upload/{root.uuid}", data={"upload_modifiers": "{}"},
                                     files={"archive": ("upload.tar", b"not a tar file", "application/x-tar")})

        assert response.status_code == 400


class TestClear:
    @pytest.mark.asyncio
    async def test_clears_the_storage_directory(self, client: AsyncClient):
        root, _ = _root_with_a_file()
        lock_uuid = str(uuid.uuid4())
        assert acquire_lock(root.uuid, lock_uuid)

        response = await client.post(f"/engine/clear/{root.uuid}/{lock_uuid}")

        assert response.status_code == 200
        assert response.json() == {"result": True}
        assert not os.path.exists(root.storage_dir)

    @pytest.mark.asyncio
    async def test_needs_the_lock_that_holds_it(self, client: AsyncClient):
        root, _ = _root_with_a_file()
        assert acquire_lock(root.uuid, str(uuid.uuid4()))

        response = await client.post(f"/engine/clear/{root.uuid}/{uuid.uuid4()}")

        assert response.status_code == 409
        assert os.path.exists(root.storage_dir)

    @pytest.mark.asyncio
    async def test_an_unknown_target(self, client: AsyncClient):
        root, _ = _root_with_a_file()
        lock_uuid = str(uuid.uuid4())
        assert acquire_lock(root.uuid, lock_uuid)

        # the lock is for another target
        assert (await client.post(f"/engine/clear/{uuid.uuid4()}/{lock_uuid}")).status_code == 409
        assert os.path.exists(root.storage_dir)

    @pytest.mark.asyncio
    async def test_is_not_a_get(self, client: AsyncClient):
        """The legacy route cleared a directory on a GET."""
        root, _ = _root_with_a_file()
        lock_uuid = str(uuid.uuid4())
        assert acquire_lock(root.uuid, lock_uuid)

        assert (await client.get(f"/engine/clear/{root.uuid}/{lock_uuid}")).status_code == 405
        assert os.path.exists(root.storage_dir)
