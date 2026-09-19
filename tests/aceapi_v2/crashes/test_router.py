"""Tests for the analysis module crash report endpoints.

These are integration tests because authentication is database backed.
"""

import io
import json
import os
import uuid
import zipfile

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from saq.crash_report import (
    CRASH_TYPE_EXCEPTION,
    FILE_DIR,
    METADATA_FILE,
    STACK_TRACE_FILE,
    get_crash_report_dir,
)
from saq.database.model import AnalysisModuleCrash
from saq.environment import get_data_dir, get_global_runtime_settings

pytestmark = pytest.mark.integration

MALWARE_BYTES = "definitely not a real macro"


def _write_report(crash_id: str, *, node: str, with_file: bool = True) -> str:
    """Write a real crash report directory on disk and return its path."""
    crash_dir = get_crash_report_dir(crash_id)
    os.makedirs(os.path.join(crash_dir, FILE_DIR), exist_ok=True)

    metadata = {
        "crash_id": crash_id,
        "crash_type": CRASH_TYPE_EXCEPTION,
        "timestamp": "2026-09-16T12:00:00",
        "node": node,
        "hostname": "test-host",
        "pid": 4711,
        "module_path": "saq.modules.test:BasicTestAnalysis",
        "module_name": "basic_test",
        "analysis_mode": "test_groups",
        "root_uuid": str(uuid.uuid4()),
        "observable_type": "file",
        "observable_value": "a" * 64,
        "exception_type": "RuntimeError",
        "exception_message": "testing failure case",
        "file_name": "malware.doc" if with_file else None,
        "omitted": [],
    }

    with open(os.path.join(crash_dir, METADATA_FILE), "w") as fp:
        json.dump(metadata, fp)

    with open(os.path.join(crash_dir, STACK_TRACE_FILE), "w") as fp:
        fp.write("EXCEPTION\ntesting failure case\n")

    if with_file:
        with open(os.path.join(crash_dir, FILE_DIR, "malware.doc"), "w") as fp:
            fp.write(MALWARE_BYTES)

    return crash_dir


async def _index(session: AsyncSession, crash_id: str, crash_dir: str, node: str, **overrides):
    row = AnalysisModuleCrash(
        uuid=crash_id,
        crash_type=overrides.get("crash_type", CRASH_TYPE_EXCEPTION),
        node=node,
        report_dir=os.path.relpath(crash_dir, start=get_data_dir()),
        module_path=overrides.get("module_path", "saq.modules.test:BasicTestAnalysis"),
        module_name=overrides.get("module_name", "basic_test"),
        analysis_mode="test_groups",
        root_uuid=overrides.get("root_uuid", str(uuid.uuid4())),
        observable_type="file",
        observable_value="a" * 64,
        exception_type="RuntimeError",
        exception_message="testing failure case",
        has_file=True,
    )
    session.add(row)
    await session.flush()
    return row


@pytest.fixture
def local_node() -> str:
    return get_global_runtime_settings().saq_node


class TestAuth:
    @pytest.mark.asyncio
    async def test_list_requires_auth(self, unauth_client: AsyncClient):
        assert (await unauth_client.get("/crashes/")).status_code == 401

    @pytest.mark.asyncio
    async def test_get_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.get(f"/crashes/{uuid.uuid4()}")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_download_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.get(f"/crashes/{uuid.uuid4()}/download")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_requires_crash_read(self, noperm_client: AsyncClient):
        """A crash report archive is live malware; it is behind its own permission."""
        assert (await noperm_client.get("/crashes/")).status_code == 403
        response = await noperm_client.get(f"/crashes/{uuid.uuid4()}/download")
        assert response.status_code == 403


class TestCrashIdValidation:
    """The crash id becomes a filesystem path and then an archive handed to an analyst."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad_id", ["not-a-crash-id", "..", "%2e%2e", "0" * 40])
    async def test_malformed_id_rejected(self, client: AsyncClient, bad_id: str):
        response = await client.get(f"/crashes/{bad_id}")
        assert response.status_code in (400, 404)
        if response.status_code == 400:
            assert response.json()["detail"] == "invalid crash id"

    @pytest.mark.asyncio
    async def test_traversal_rejected(self, client: AsyncClient):
        response = await client.get("/crashes/..%2F..%2F..%2Fetc%2Fpasswd/download")
        assert response.status_code in (400, 404)

    @pytest.mark.asyncio
    async def test_unknown_id_is_404(self, client: AsyncClient):
        response = await client.get(f"/crashes/{uuid.uuid4()}")
        assert response.status_code == 404


class TestGetCrashReport:
    @pytest.mark.asyncio
    async def test_detail(self, client: AsyncClient, session: AsyncSession, local_node: str):
        crash_id = str(uuid.uuid4())
        crash_dir = _write_report(crash_id, node=local_node)
        await _index(session, crash_id, crash_dir, local_node)

        response = await client.get(f"/crashes/{crash_id}")
        assert response.status_code == 200

        body = response.json()
        assert body["crash_id"] == crash_id
        assert body["crash_type"] == CRASH_TYPE_EXCEPTION
        assert body["module_name"] == "basic_test"
        assert body["exception_type"] == "RuntimeError"
        assert body["complete"] is True
        assert body["file_name"] == "malware.doc"

        listed = {f["path"] for f in body["files"]}
        assert METADATA_FILE in listed
        assert STACK_TRACE_FILE in listed
        assert os.path.join(FILE_DIR, "malware.doc") in listed

    @pytest.mark.asyncio
    async def test_detail_without_index_row(self, client: AsyncClient, local_node: str):
        """A report whose index insert failed is still fetchable by id."""
        crash_id = str(uuid.uuid4())
        _write_report(crash_id, node=local_node)

        response = await client.get(f"/crashes/{crash_id}")
        assert response.status_code == 200
        assert response.json()["crash_id"] == crash_id

    @pytest.mark.asyncio
    async def test_incomplete_report_is_served(self, client: AsyncClient, local_node: str):
        """A worker killed while writing its own crash report still leaves evidence."""
        crash_id = str(uuid.uuid4())
        crash_dir = _write_report(crash_id, node=local_node)
        os.remove(os.path.join(crash_dir, METADATA_FILE))

        response = await client.get(f"/crashes/{crash_id}")
        assert response.status_code == 200

        body = response.json()
        assert body["complete"] is False
        # with no metadata and no index row there is genuinely nothing that says what kind of
        # crash it was, and the response says so rather than guessing
        assert body["crash_type"] == "unknown"



class TestDownloadCrashReport:
    @pytest.mark.asyncio
    async def test_download_happy_path(
        self, client: AsyncClient, session: AsyncSession, local_node: str, tmp_path
    ):
        crash_id = str(uuid.uuid4())
        crash_dir = _write_report(crash_id, node=local_node)
        await _index(session, crash_id, crash_dir, local_node)

        response = await client.get(f"/crashes/{crash_id}/download")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/zip"
        assert f"crash-{crash_id}.zip" in response.headers["content-disposition"]

        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            names = archive.namelist()
            assert f"{crash_id}/{METADATA_FILE}" in names
            assert f"{crash_id}/{STACK_TRACE_FILE}" in names
            assert f"{crash_id}/{FILE_DIR}/malware.doc" in names

            # encrypted with the malware-handling convention password
            archive.extractall(str(tmp_path), pwd=b"infected")

        extracted = tmp_path / crash_id / FILE_DIR / "malware.doc"
        assert extracted.read_text() == MALWARE_BYTES

    @pytest.mark.asyncio
    async def test_download_is_encrypted(
        self, client: AsyncClient, local_node: str, tmp_path
    ):
        """Without the password the archive does not open -- it survives AV on the way."""
        crash_id = str(uuid.uuid4())
        _write_report(crash_id, node=local_node)

        response = await client.get(f"/crashes/{crash_id}/download")
        assert response.status_code == 200

        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            with pytest.raises(RuntimeError):
                archive.read(f"{crash_id}/{FILE_DIR}/malware.doc")

    @pytest.mark.asyncio
    async def test_download_unknown_id(self, client: AsyncClient):
        response = await client.get(f"/crashes/{uuid.uuid4()}/download")
        assert response.status_code == 404



class TestListCrashReports:
    @pytest.mark.asyncio
    async def test_filter_by_root_uuid(
        self, client: AsyncClient, session: AsyncSession, local_node: str
    ):
        """The route an analyst takes when they have the alert but not the crash id."""
        root_uuid = str(uuid.uuid4())

        wanted = str(uuid.uuid4())
        await _index(session, wanted, _write_report(wanted, node=local_node), local_node,
                     root_uuid=root_uuid)

        other = str(uuid.uuid4())
        await _index(session, other, _write_report(other, node=local_node), local_node)

        response = await client.get("/crashes/", params={"root_uuid": root_uuid})
        assert response.status_code == 200

        rows = response.json()["data"]
        assert [row["crash_id"] for row in rows] == [wanted]
        assert rows[0]["local"] is True

    @pytest.mark.asyncio
    async def test_filter_by_module_name_or_path(
        self, client: AsyncClient, session: AsyncSession, local_node: str
    ):
        crash_id = str(uuid.uuid4())
        await _index(session, crash_id, _write_report(crash_id, node=local_node), local_node,
                     module_name="unique_test_module",
                     module_path="saq.modules.test:UniqueTestAnalysis")

        by_name = await client.get("/crashes/", params={"module": "unique_test_module"})
        assert [r["crash_id"] for r in by_name.json()["data"]] == [crash_id]

        by_path = await client.get(
            "/crashes/", params={"module": "saq.modules.test:UniqueTestAnalysis"}
        )
        assert [r["crash_id"] for r in by_path.json()["data"]] == [crash_id]

    @pytest.mark.asyncio
    async def test_remote_reports_are_listed_but_marked_non_local(
        self, client: AsyncClient, session: AsyncSession
    ):
        """The index is cluster-wide even though the reports are not."""
        root_uuid = str(uuid.uuid4())
        crash_id = str(uuid.uuid4())
        await _index(session, crash_id, _write_report(crash_id, node="other-node"), "other-node",
                     root_uuid=root_uuid)

        response = await client.get("/crashes/", params={"root_uuid": root_uuid})
        rows = response.json()["data"]
        assert len(rows) == 1
        assert rows[0]["local"] is False
        assert rows[0]["node"] == "other-node"

    @pytest.mark.asyncio
    async def test_limit_is_bounded(self, client: AsyncClient):
        assert (await client.get("/crashes/", params={"limit": 5000})).status_code == 422
        assert (await client.get("/crashes/", params={"limit": 0})).status_code == 422


class TestCrossNodeViaSharedStorage:
    """Serving a report that is NOT on this node's disk, from shared object storage.

    'The analyst is on a different node' is simulated the honest way: replicate the report, then
    delete the local directory. That is exactly what node B's disk looks like. The store is a real
    LocalStorage on a tmp dir, so these exercise genuine upload/download rather than mocks.
    """

    @pytest.fixture
    def shared_storage(self, tmp_path, monkeypatch):
        from saq.configuration.config import get_config
        from saq.storage.adapter import StorageAdapter
        from saq.storage.local import LocalStorage

        adapter = StorageAdapter(LocalStorage(base_dir=str(tmp_path / "shared")))
        monkeypatch.setattr("saq.storage.factory.STORAGE_SYSTEM", adapter)
        monkeypatch.setattr(get_config().crash_reporting, "replicate", True)
        return adapter

    def _replicate_and_go_remote(self, crash_id: str, crash_dir: str) -> None:
        """Push the report to shared storage, then remove the local copy."""
        import shutil

        from saq.crash_replication import replicate_report

        assert replicate_report(crash_dir, crash_id) is True
        shutil.rmtree(crash_dir)

    @pytest.mark.asyncio
    async def test_detail_served_from_shared_storage(
        self, client: AsyncClient, session: AsyncSession, shared_storage
    ):
        crash_id = str(uuid.uuid4())
        crash_dir = _write_report(crash_id, node="some-other-node")
        await _index(session, crash_id, crash_dir, "some-other-node")
        self._replicate_and_go_remote(crash_id, crash_dir)

        response = await client.get(f"/crashes/{crash_id}")
        assert response.status_code == 200

        body = response.json()
        assert body["crash_id"] == crash_id
        assert body["complete"] is True
        assert body["remote"] is True
        # node still says where it came from, even though we served it
        assert body["node"] == "some-other-node"
        assert body["module_name"] == "basic_test"

        listed = {f["path"] for f in body["files"]}
        assert METADATA_FILE in listed
        assert os.path.join(FILE_DIR, "malware.doc") in listed
        # sizes come from the object store, not from a local stat
        assert all(f["size"] > 0 for f in body["files"])

    @pytest.mark.asyncio
    async def test_download_served_from_shared_storage(
        self, client: AsyncClient, session: AsyncSession, shared_storage, tmp_path
    ):
        crash_id = str(uuid.uuid4())
        crash_dir = _write_report(crash_id, node="some-other-node")
        await _index(session, crash_id, crash_dir, "some-other-node")
        self._replicate_and_go_remote(crash_id, crash_dir)

        response = await client.get(f"/crashes/{crash_id}/download")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/zip"

        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            assert f"{crash_id}/{METADATA_FILE}" in archive.namelist()
            archive.extractall(str(tmp_path / "out"), pwd=b"infected")

        extracted = tmp_path / "out" / crash_id / FILE_DIR / "malware.doc"
        assert extracted.read_text() == MALWARE_BYTES

    @pytest.mark.asyncio
    async def test_download_cleans_up_its_staging_directory(
        self, client: AsyncClient, session: AsyncSession, shared_storage
    ):
        """The fetched copy is staged under the temp dir and torn down before responding, so the
        router's single BackgroundTask(unlink, zip) stays the whole cleanup story."""
        import glob as _glob

        from saq.environment import get_temp_dir

        crash_id = str(uuid.uuid4())
        crash_dir = _write_report(crash_id, node="some-other-node")
        await _index(session, crash_id, crash_dir, "some-other-node")
        self._replicate_and_go_remote(crash_id, crash_dir)

        assert (await client.get(f"/crashes/{crash_id}/download")).status_code == 200
        assert _glob.glob(os.path.join(get_temp_dir(), f"crash-fetch-{crash_id}-*")) == []

    @pytest.mark.asyncio
    async def test_remote_owned_but_not_replicated_still_409(
        self, client: AsyncClient, session: AsyncSession, shared_storage
    ):
        """Replication on, but this particular report never made it to the bucket."""
        import shutil

        crash_id = str(uuid.uuid4())
        crash_dir = _write_report(crash_id, node="some-other-node")
        await _index(session, crash_id, crash_dir, "some-other-node")
        shutil.rmtree(crash_dir)

        response = await client.get(f"/crashes/{crash_id}")
        assert response.status_code == 409

        detail = response.json()["detail"]
        assert detail["node"] == "some-other-node"
        # the 409 explains its own fix rather than just naming a host
        assert "crash sync" in detail["message"]

        assert (await client.get(f"/crashes/{crash_id}/download")).status_code == 409

    @pytest.mark.asyncio
    async def test_listing_marks_remote_reports_reachable(
        self, client: AsyncClient, session: AsyncSession, shared_storage
    ):
        """With replication on, `local` means 'downloadable from here', not 'written here'."""
        root_uuid = str(uuid.uuid4())
        crash_id = str(uuid.uuid4())
        crash_dir = _write_report(crash_id, node="other-node")
        await _index(session, crash_id, crash_dir, "other-node", root_uuid=root_uuid)

        response = await client.get("/crashes/", params={"root_uuid": root_uuid})
        rows = response.json()["data"]
        assert len(rows) == 1
        assert rows[0]["node"] == "other-node"
        assert rows[0]["local"] is True


class TestWrongNodeWithoutReplication:
    """With replication off, node identity IS the access decision and the 409 is unchanged.

    These re-scope the original wrong-node tests, which wrote the report to the LOCAL directory
    and indexed it as another node. Under the new local-first resolution that combination is
    served rather than refused, so the node check only applies when replication is off.
    """

    @pytest.fixture(autouse=True)
    def replication_off(self, monkeypatch):
        from saq.configuration.config import get_config

        monkeypatch.setattr(get_config().crash_reporting, "replicate", False)

    @pytest.mark.asyncio
    async def test_detail_409(self, client: AsyncClient, session: AsyncSession):
        crash_id = str(uuid.uuid4())
        crash_dir = _write_report(crash_id, node="some-other-node")
        await _index(session, crash_id, crash_dir, "some-other-node")

        response = await client.get(f"/crashes/{crash_id}")
        assert response.status_code == 409

        detail = response.json()["detail"]
        assert detail["error"] == "wrong_node"
        assert detail["node"] == "some-other-node"
        # points the operator at the setting that would make this work
        assert "crash_reporting.replicate" in detail["message"]

    @pytest.mark.asyncio
    async def test_download_409(self, client: AsyncClient, session: AsyncSession):
        crash_id = str(uuid.uuid4())
        crash_dir = _write_report(crash_id, node="some-other-node")
        await _index(session, crash_id, crash_dir, "some-other-node")

        assert (await client.get(f"/crashes/{crash_id}/download")).status_code == 409

    @pytest.mark.asyncio
    async def test_listing_marks_remote_reports_unreachable(
        self, client: AsyncClient, session: AsyncSession
    ):
        root_uuid = str(uuid.uuid4())
        crash_id = str(uuid.uuid4())
        await _index(session, crash_id, _write_report(crash_id, node="other-node"), "other-node",
                     root_uuid=root_uuid)

        response = await client.get("/crashes/", params={"root_uuid": root_uuid})
        rows = response.json()["data"]
        assert rows[0]["local"] is False
