"""Tests for aceapi_v2 alerts router — bulk add observable endpoint."""

import hashlib
import json
import logging
import os
import shutil
import zipfile
from datetime import datetime
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from aceapi_v2.application import app
from saq.analysis.root import RootAnalysis, load_root
from saq.constants import ANALYSIS_MODE_CORRELATION
from saq.database import get_db
from saq.database.model import (
    Alert,
    Comment,
    Observable,
    ObservableComment,
    ObservableMapping,
    User,
)
from saq.database.util.locking import acquire_lock, release_lock
from saq.environment import get_base_dir
from saq.search.tasks import submit_index_task
from tests.aceapi_v2.conftest import audit_actor_of, audit_record
from tests.saq.helpers import insert_alert, make_simulated, workload_count

pytestmark = pytest.mark.integration


VALID_UUID = "11111111-2222-3333-4444-555555555555"


def _storage_path(alert: Alert) -> str:
    return os.path.join(get_base_dir(), alert.storage_dir)


def _load_alert_root(alert: Alert) -> RootAnalysis:
    """The alert's analysis as the endpoint left it on disk."""
    return load_root(_storage_path(alert))


def _assert_unlocked(alert_uuid: str):
    """The request released its lock: anyone can take the alert again."""
    lock_uuid = str(uuid4())
    assert acquire_lock(alert_uuid, lock_uuid)
    release_lock(alert_uuid, lock_uuid)


def _archive(alert: Alert):
    db = get_db()
    db.query(Alert).filter(Alert.id == alert.id).update({"archived": True})
    db.commit()


def _insert_alert_row(alert_uuid: str, storage_dir: str) -> Alert:
    """An alert row (no analysis) whose storage directory is ``storage_dir``."""
    db = get_db()
    alert = Alert(
        uuid=alert_uuid,
        location="test-location",
        storage_dir=storage_dir,  # absolute; os.path.join discards get_base_dir()
        tool="test-tool",
        tool_instance="test-tool-instance",
        alert_type="test",
    )
    db.add(alert)
    db.commit()
    return alert


class TestBulkAddObservable:
    """Test the POST /alerts/bulk-add-observable endpoint."""

    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        """Unauthenticated requests should return 401."""
        response = await unauth_client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": ["abc-123"],
            "observable_type": "ipv4",
            "observable_value": "1.2.3.4",
        })
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_empty_uuids(self, client: AsyncClient):
        """Empty alert_uuids list should return 400."""
        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": [],
            "observable_type": "ipv4",
            "observable_value": "1.2.3.4",
        })
        assert response.status_code == 400
        assert "No alert UUIDs" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_missing_value(self, client: AsyncClient):
        """Empty observable_value should return 400."""
        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": ["abc-123"],
            "observable_type": "ipv4",
            "observable_value": "",
        })
        assert response.status_code == 400
        assert "Missing observable value" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_missing_fields(self, client: AsyncClient):
        """Missing required fields should return 422."""
        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": ["abc-123"],
        })
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_invalid_time_format(self, client: AsyncClient):
        """Invalid time format should return 400."""
        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": ["abc-123"],
            "observable_type": "ipv4",
            "observable_value": "1.2.3.4",
            "observable_time": "not-a-date",
        })
        assert response.status_code == 400
        assert "Invalid time format" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_unknown_observable_type(self, client: AsyncClient):
        """A type the registry does not publish can never succeed against any alert, so it is a
        request-level 400 -- and no alert is locked or loaded for it."""
        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": ["uuid-1"],
            "observable_type": "not_a_real_type",
            "observable_value": "whatever",
        })
        assert response.status_code == 400
        assert "not a valid observable type" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_a_simulated_alert_is_reported_as_a_failure(self, client: AsyncClient):
        """A SIMULATED alert gets no new observables and is not analyzed again (docs/SVS_RUNS.md)."""
        simulated, other = insert_alert(), insert_alert()
        make_simulated(simulated)

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": [simulated.uuid, other.uuid],
            "observable_type": "fqdn",
            "observable_value": "evil.example.com",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["failed_uuids"] == [simulated.uuid]
        assert data["failed_details"][simulated.uuid].startswith(
            f"alert {simulated.uuid} is SIMULATED, a disposition only ACE sets")
        assert data["success_count"] == 1
        assert workload_count(simulated.uuid) == 0

    @pytest.mark.asyncio
    async def test_invalid_value_is_reported_as_a_failure(self, client: AsyncClient):
        """add_observable_by_spec returns None for a value that is impossible for its type.
        That is reported as a per-alert failure and does not schedule a correlation pass."""
        alert = insert_alert()
        version = alert.version

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": [alert.uuid],
            "observable_type": "ipv4",
            "observable_value": "not-an-ip",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["success_count"] == 0
        assert data["failed_count"] == 1
        assert data["failed_uuids"] == [alert.uuid]
        assert "not a valid value for observable type ipv4" in data["failed_details"][alert.uuid]

        # nothing was written and no analysis was scheduled
        assert _load_alert_root(alert).get_observables_by_type("ipv4") == []
        get_db().expire_all()
        assert get_db().query(Alert.version).filter(Alert.id == alert.id).scalar() == version
        assert workload_count(alert.uuid) == 0
        _assert_unlocked(alert.uuid)

    @pytest.mark.asyncio
    async def test_bulk_add_observable_success(self, client: AsyncClient, client_actor,
                                               caplog: pytest.LogCaptureFixture):
        """Successfully adding an observable to multiple alerts."""
        caplog.set_level(logging.INFO)
        alert1, alert2 = insert_alert(), insert_alert()
        versions = {alert1.id: alert1.version, alert2.id: alert2.version}

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": [alert1.uuid, alert2.uuid],
            "observable_type": "fqdn",
            "observable_value": "evil.example.com",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["success_count"] == 2
        assert data["failed_count"] == 0
        assert data["failed_uuids"] == []
        audit = audit_record(caplog, "user unittest bulk-added observable (fqdn,evil.example.com,None)")
        assert (*audit_actor_of(audit), audit.alert_uuids, audit.observable_type, audit.observable_value) == (
            *client_actor, [alert1.uuid, alert2.uuid], "fqdn", "evil.example.com")

        # each alert got the observable, was put back into correlation and queued for analysis
        for alert in (alert1, alert2):
            root = _load_alert_root(alert)
            assert root.get_observable_by_spec("fqdn", "evil.example.com") is not None
            assert root.analysis_mode == ANALYSIS_MODE_CORRELATION
            assert workload_count(alert.uuid) == 1
            _assert_unlocked(alert.uuid)

            # sync() wrote the row and indexed the new observable
            get_db().expire_all()
            assert get_db().query(Alert.version).filter(Alert.id == alert.id).scalar() != versions[alert.id]
            assert get_db().query(Observable).join(
                ObservableMapping, ObservableMapping.observable_id == Observable.id).filter(
                ObservableMapping.alert_id == alert.id,
                Observable.type == "fqdn",
                Observable.value == b"evil.example.com").count() == 1

    @pytest.mark.asyncio
    async def test_bulk_add_observable_with_time(self, client: AsyncClient):
        """Observable time should be parsed and set on the added observable."""
        alert = insert_alert()

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": [alert.uuid],
            "observable_type": "ipv4",
            "observable_value": "10.0.0.1",
            "observable_time": "2026-03-31 12:00:00",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["success_count"] == 1

        (observable,) = _load_alert_root(alert).get_observables_by_type("ipv4")
        assert observable.value == "10.0.0.1"
        assert isinstance(observable.time, datetime)
        assert observable.time.strftime("%Y-%m-%d %H:%M:%S") == "2026-03-31 12:00:00"

    @pytest.mark.asyncio
    async def test_bulk_add_observable_with_directives(self, client: AsyncClient):
        """Directives should be applied to the created observable."""
        alert = insert_alert()

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": [alert.uuid],
            "observable_type": "url",
            "observable_value": "https://bad.example.com",
            "directives": ["crawl", "sandbox"],
        })

        assert response.status_code == 200
        data = response.json()
        assert data["success_count"] == 1

        observable = _load_alert_root(alert).get_observable_by_spec("url", "https://bad.example.com")
        assert observable.has_directive("crawl")
        assert observable.has_directive("sandbox")

    @pytest.mark.asyncio
    async def test_bulk_add_observable_lock_failure(self, client: AsyncClient):
        """Alerts that can't be locked should be reported as failed."""
        alert = insert_alert()
        engine_lock = str(uuid4())
        assert acquire_lock(alert.uuid, engine_lock)
        try:
            response = await client.post("/alerts/bulk-add-observable", json={
                "alert_uuids": [alert.uuid],
                "observable_type": "ipv4",
                "observable_value": "1.2.3.4",
            })

            # the request did not take over or release the lock somebody else holds
            assert not acquire_lock(alert.uuid, str(uuid4()))
        finally:
            release_lock(alert.uuid, engine_lock)

        assert response.status_code == 200
        data = response.json()
        assert data["success_count"] == 0
        assert data["failed_count"] == 1
        assert data["failed_uuids"] == [alert.uuid]
        assert data["failed_details"][alert.uuid] == "alert is currently locked"
        assert _load_alert_root(alert).get_observables_by_type("ipv4") == []
        assert workload_count(alert.uuid) == 0

    @pytest.mark.asyncio
    async def test_bulk_add_observable_nonexistent_alert(self, client: AsyncClient):
        """Nonexistent alerts should be reported as failed."""
        missing = str(uuid4())

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": [missing],
            "observable_type": "fqdn",
            "observable_value": "evil.example.com",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["success_count"] == 0
        assert data["failed_count"] == 1
        assert data["failed_uuids"] == [missing]
        assert data["failed_details"][missing] == "alert not found"

    @pytest.mark.asyncio
    async def test_bulk_add_observable_partial_failure(self, client: AsyncClient):
        """Mix of successful and failed alerts should be reported correctly."""
        alert = insert_alert()
        missing = str(uuid4())

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": [alert.uuid, missing],
            "observable_type": "fqdn",
            "observable_value": "evil.example.com",
        })

        assert response.status_code == 200
        data = response.json()
        assert data["success_count"] == 1
        assert data["failed_count"] == 1
        assert data["failed_uuids"] == [missing]
        assert data["failed_details"][missing] == "alert not found"
        assert _load_alert_root(alert).get_observable_by_spec("fqdn", "evil.example.com") is not None
        assert workload_count(alert.uuid) == 1

    @pytest.mark.asyncio
    async def test_bulk_add_observable_invalid_directives_filtered(self, client: AsyncClient):
        """Invalid directives should be silently filtered out."""
        alert = insert_alert()

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": [alert.uuid],
            "observable_type": "ipv4",
            "observable_value": "1.2.3.4",
            "directives": ["sandbox", "totally_fake_directive"],
        })

        assert response.status_code == 200
        data = response.json()
        assert data["success_count"] == 1

        # Only valid directive should be applied
        observable = _load_alert_root(alert).get_observable_by_spec("ipv4", "1.2.3.4")
        assert observable.directives == ["sandbox"]

    @pytest.mark.asyncio
    async def test_bulk_add_observable_stamps_added_by(self, client: AsyncClient):
        """A newly added observable should be stamped with the auth user and time."""
        alert = insert_alert()

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": [alert.uuid],
            "observable_type": "fqdn",
            "observable_value": "evil.example.com",
        })

        assert response.status_code == 200
        assert response.json()["success_count"] == 1

        # the api auth fixture authenticates as the unittest user
        observable = _load_alert_root(alert).get_observable_by_spec("fqdn", "evil.example.com")
        assert observable.added_by == "unittest"
        assert isinstance(observable.added_time, datetime)

    @pytest.mark.asyncio
    async def test_bulk_add_observable_existing_not_stamped(self, client: AsyncClient):
        """An observable that already existed in the alert should not be stamped."""
        alert = insert_alert()
        # the observable already exists in the alert (e.g. added by the engine)
        root = _load_alert_root(alert)
        existing = root.add_observable_by_spec("fqdn", "evil.example.com")
        root.save()

        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": [alert.uuid],
            "observable_type": "fqdn",
            "observable_value": "evil.example.com",
        })

        assert response.status_code == 200
        assert response.json()["success_count"] == 1

        observable = _load_alert_root(alert).get_observable_by_spec("fqdn", "evil.example.com")
        assert observable.uuid == existing.uuid
        assert observable.added_by is None
        assert observable.added_time is None

    @pytest.mark.asyncio
    async def test_valid_time_format(self, client: AsyncClient):
        """Valid time format should be accepted (regression check)."""
        response = await client.post("/alerts/bulk-add-observable", json={
            "alert_uuids": [str(uuid4())],
            "observable_type": "ipv4",
            "observable_value": "1.2.3.4",
            "observable_time": "2026-03-31 14:30:00",
        })

        # the unknown alert is a per-alert failure, not a 400 for the time format
        assert response.status_code == 200
        assert response.json()["failed_details"] != {}


class TestDownloadAlert:
    """Test the GET /alerts/{alert_uuid}/download endpoint."""

    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.get(f"/alerts/{VALID_UUID}/download")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_uuid(self, client: AsyncClient):
        response = await client.get("/alerts/not-a-uuid/download")
        assert response.status_code == 400
        assert "invalid alert UUID" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_alert_not_found(self, client: AsyncClient):
        response = await client.get(f"/alerts/{uuid4()}/download")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_archived_alert(self, client: AsyncClient):
        alert = insert_alert()
        _archive(alert)
        response = await client.get(f"/alerts/{alert.uuid}/download")
        assert response.status_code == 410

    @pytest.mark.asyncio
    async def test_missing_storage_dir(self, client: AsyncClient):
        alert = insert_alert()
        shutil.rmtree(_storage_path(alert))
        response = await client.get(f"/alerts/{alert.uuid}/download")
        assert response.status_code == 410

    @pytest.mark.asyncio
    async def test_download_happy_path(self, client: AsyncClient, client_actor, tmp_path,
                                       caplog: pytest.LogCaptureFixture):
        caplog.set_level(logging.INFO)
        alert = insert_alert()
        alert_uuid = alert.uuid
        storage_dir = _storage_path(alert)
        with open(os.path.join(storage_dir, "saq.log"), "w") as fp:
            fp.write("log line one\nlog line two\n")

        db = get_db()
        db.add(Comment(uuid=alert_uuid, user_id=_unittest_user_id(), comment="looks bad"))
        db.commit()

        response = await client.get(f"/alerts/{alert_uuid}/download")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/zip"
        assert f"{alert_uuid}.zip" in response.headers["content-disposition"]
        audit = audit_record(caplog, f"user unittest downloading alert {alert_uuid}")
        assert (*audit_actor_of(audit), audit.alert_uuid) == (*client_actor, alert_uuid)

        # Verify the zip is real and encrypted with 'infected'.
        zip_bytes = response.content
        zip_path = tmp_path / "downloaded.zip"
        zip_path.write_bytes(zip_bytes)

        # Every entry must be nested under a "<uuid>/" subdirectory.
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            assert all(n.startswith(f"{alert_uuid}/") for n in names)
            assert f"{alert_uuid}/saq.log" in names
            assert f"{alert_uuid}/data.json" in names
            assert f"{alert_uuid}/comments.json" in names

        # The `unzip` binary can decrypt ZipCrypto; Python's stdlib zipfile can too
        # when given the right password.
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(extract_dir, pwd=b"infected")
        # The alert's files extract into the "<uuid>/" subdirectory.
        extracted_log = extract_dir / alert_uuid / "saq.log"
        assert extracted_log.is_file()
        assert extracted_log.read_text() == "log line one\nlog line two\n"
        assert load_root(str(extract_dir / alert_uuid)).uuid == alert_uuid

        comments = json.loads((extract_dir / alert_uuid / "comments.json").read_text())
        assert comments["alert_uuid"] == alert_uuid
        assert [(c["comment"], c["user"]["username"]) for c in comments["alert_comments"]] == [
            ("looks bad", "unittest"),
        ]
        assert comments["observable_comments"] == []

        # the comments file was staged in a temp dir, never written into the alert
        assert not os.path.exists(os.path.join(storage_dir, "comments.json"))

    @pytest.mark.asyncio
    async def test_download_includes_comments(self, client: AsyncClient, tmp_path):
        """Alert comments and observable comments exist only in the database, so the
        download has to pull them in as ``<uuid>/comments.json``."""
        alert_uuid = str(uuid4())
        storage_dir = tmp_path / alert_uuid
        storage_dir.mkdir()
        (storage_dir / "data.json").write_text("{}")

        alert = _insert_alert_row(alert_uuid, str(storage_dir))
        db = get_db()
        user = db.query(User).filter(User.username == "unittest").one()

        # a comment on a different alert must not leak in
        db.add(Comment(uuid=str(uuid4()), user_id=user.id, comment="other alert"))
        db.add(Comment(uuid=alert_uuid, user_id=user.id, comment="first alert comment"))
        db.add(Comment(uuid=alert_uuid, user_id=user.id, comment="second alert comment"))

        value = b"192.0.2.1"
        observable = Observable(type="ipv4", sha256=hashlib.sha256(value).digest(), value=value)
        db.add(observable)
        db.flush()
        db.add(ObservableMapping(alert_id=alert.id, observable_id=observable.id))
        db.add(ObservableComment(user_id=user.id, observable_id=observable.id, comment="known scanner"))

        # an observable commented on but not mapped to this alert must not leak in
        other_value = b"198.51.100.1"
        other = Observable(type="ipv4", sha256=hashlib.sha256(other_value).digest(), value=other_value)
        db.add(other)
        db.flush()
        db.add(ObservableComment(user_id=user.id, observable_id=other.id, comment="unrelated"))
        db.commit()

        response = await client.get(f"/alerts/{alert_uuid}/download")
        assert response.status_code == 200

        zip_path = tmp_path / "downloaded.zip"
        zip_path.write_bytes(response.content)
        extract_dir = tmp_path / "extracted"
        extract_dir.mkdir()
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(extract_dir, pwd=b"infected")

        comments = json.loads((extract_dir / alert_uuid / "comments.json").read_text())
        assert comments["alert_uuid"] == alert_uuid

        assert [c["comment"] for c in comments["alert_comments"]] == [
            "first alert comment",
            "second alert comment",
        ]
        for c in comments["alert_comments"]:
            assert c["user"]["username"] == "unittest"
            assert c["insert_date"]

        assert len(comments["observable_comments"]) == 1
        oc = comments["observable_comments"][0]
        assert oc["comment"] == "known scanner"
        assert oc["user"]["username"] == "unittest"
        assert oc["observable"] == {
            "type": "ipv4",
            "value": "192.0.2.1",
            "sha256": hashlib.sha256(value).hexdigest(),
        }

    @pytest.mark.asyncio
    async def test_storage_dir_basename_mismatch(self, client: AsyncClient, tmp_path):
        # A storage directory not named after the alert UUID trips the guard.
        storage_dir = tmp_path / "not-the-uuid"
        storage_dir.mkdir()
        alert = _insert_alert_row(str(uuid4()), str(storage_dir))
        response = await client.get(f"/alerts/{alert.uuid}/download")
        assert response.status_code == 500


class TestUnhandledException:
    """An unhandled exception in an endpoint should return a 500 and be logged
    with a traceback through the application logger (not only uvicorn's stderr)."""

    @pytest.mark.asyncio
    @patch(
        "aceapi_v2.alerts.service.create_encrypted_alert_zip",
        side_effect=RuntimeError("boom"),
    )
    async def test_unhandled_exception_logged_and_returns_500(
        self, mock_create_zip, _override_db_session, valid_api_key: str, caplog, monkeypatch
    ):
        write_error_report = MagicMock()
        monkeypatch.setattr("saq.error.reporting.write_error_report", write_error_report)

        # starlette's ServerErrorMiddleware re-raises after building the response so
        # the server can still log it; disable raise_app_exceptions so we can observe
        # the 500 response the catch-all handler produced
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"x-ace-auth": valid_api_key},
        ) as client:
            with caplog.at_level(logging.ERROR, logger="aceapi_v2.app_factory"):
                response = await client.get(f"/alerts/{VALID_UUID}/download")

        # the catch-all handler returns a consistent JSON 500 body
        assert response.status_code == 500
        assert response.json() == {"detail": "internal server error"}

        # the exception was logged at ERROR with a traceback by the app handler
        records = [
            r for r in caplog.records if r.name == "aceapi_v2.app_factory"
        ]
        assert records, "expected an aceapi_v2.app_factory log record"
        record = records[-1]
        assert record.levelno == logging.ERROR
        assert isinstance(record.exc_info[1], RuntimeError)

        # and the traceback on that record is what wrote the error report
        write_error_report.assert_called_once()
        assert write_error_report.call_args.kwargs["record"] is record


class TestViewAlertLogs:
    """Test the GET /alerts/{alert_uuid}/logs endpoint."""

    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.get(f"/alerts/{VALID_UUID}/logs")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_uuid(self, client: AsyncClient):
        response = await client.get("/alerts/not-a-uuid/logs")
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_alert_not_found(self, client: AsyncClient):
        response = await client.get(f"/alerts/{uuid4()}/logs")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_archived_alert(self, client: AsyncClient):
        alert = insert_alert()
        _archive(alert)
        response = await client.get(f"/alerts/{alert.uuid}/logs")
        assert response.status_code == 410

    @pytest.mark.asyncio
    async def test_log_missing(self, client: AsyncClient):
        # storage_dir exists, but saq.log is not in it
        alert = insert_alert()
        assert not os.path.exists(os.path.join(_storage_path(alert), "saq.log"))
        response = await client.get(f"/alerts/{alert.uuid}/logs")
        assert response.status_code == 404
        assert "saq.log not present" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_view_logs_inline(self, client: AsyncClient):
        alert = insert_alert()
        log_content = "2026-05-13 12:00:00 INFO module - hello\n"
        with open(os.path.join(_storage_path(alert), "saq.log"), "w") as fp:
            fp.write(log_content)

        response = await client.get(f"/alerts/{alert.uuid}/logs")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        # Inline disposition: either no disposition header or one containing 'inline'
        disposition = response.headers.get("content-disposition", "")
        assert "attachment" not in disposition
        assert response.text == log_content

    @pytest.mark.asyncio
    async def test_view_logs_download(self, client: AsyncClient):
        alert = insert_alert()
        log_content = "downloadable log content\n"
        with open(os.path.join(_storage_path(alert), "saq.log"), "w") as fp:
            fp.write(log_content)

        response = await client.get(f"/alerts/{alert.uuid}/logs?download=true")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        assert "attachment" in response.headers["content-disposition"]
        assert f"{alert.uuid}-saq.log" in response.headers["content-disposition"]
        assert response.text == log_content


class TestGetAlert:
    """Test the GET /alerts/{alert_uuid} endpoint and its ETag / If-None-Match handling."""

    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.get(f"/alerts/{VALID_UUID}")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_uuid(self, client: AsyncClient):
        response = await client.get("/alerts/not-a-uuid")
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_unknown_alert(self, client: AsyncClient):
        response = await client.get(f"/alerts/{VALID_UUID}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_returns_alert_with_version(self, client: AsyncClient):
        from tests.saq.helpers import insert_alert

        alert = insert_alert()
        response = await client.get(f"/alerts/{alert.uuid}")
        assert response.status_code == 200
        assert response.headers["ETag"] == f'"{alert.version}"'

        result = response.json()["result"]
        assert result["uuid"] == alert.uuid
        assert result["version"] == alert.version
        assert result["database_id"] == alert.id
        # the analysis tree came along, not just the row
        assert "observable_store" in result

    @pytest.mark.asyncio
    async def test_if_none_match_returns_304_until_the_alert_changes(self, client: AsyncClient):
        from saq.database.util.alert import touch_alerts
        from saq.database.pool import get_db
        from tests.saq.helpers import insert_alert

        alert = insert_alert()
        response = await client.get(f"/alerts/{alert.uuid}")
        etag = response.headers["ETag"]

        # unchanged: the cheap path answers without loading the alert
        response = await client.get(f"/alerts/{alert.uuid}", headers={"If-None-Match": etag})
        assert response.status_code == 304
        assert response.headers["ETag"] == etag
        assert response.content == b""

        # weak validators and lists are accepted too
        response = await client.get(
            f"/alerts/{alert.uuid}", headers={"If-None-Match": f'"other", W/{etag}'})
        assert response.status_code == 304

        # something changed: the full alert comes back with the new token
        touch_alerts([alert.uuid])
        get_db().commit()
        response = await client.get(f"/alerts/{alert.uuid}", headers={"If-None-Match": etag})
        assert response.status_code == 200
        assert response.headers["ETag"] != etag
        assert response.json()["result"]["version"] == response.headers["ETag"].strip('"')

    @pytest.mark.asyncio
    async def test_archived_alert_is_gone(self, client: AsyncClient):
        from saq.database.pool import get_db
        from tests.saq.helpers import insert_alert

        alert = insert_alert()
        alert.archived = True
        get_db().commit()

        response = await client.get(f"/alerts/{alert.uuid}")
        assert response.status_code == 410


def _insert_commented_alert(user_id: int, text: str = "original comment") -> tuple[str, int]:
    """An alert row with one comment by ``user_id``; returns (alert uuid, comment id)."""
    alert_uuid = str(uuid4())
    db = get_db()
    db.add(Alert(
        uuid=alert_uuid,
        location="test-location",
        storage_dir=alert_uuid,
        tool="test-tool",
        tool_instance="test-tool-instance",
        alert_type="test",
    ))
    comment = Comment(uuid=alert_uuid, user_id=user_id, comment=text)
    db.add(comment)
    db.commit()
    return alert_uuid, comment.comment_id


def _unittest_user_id() -> int:
    return get_db().query(User).filter(User.username == "unittest").one().id


def _alert_version(alert_uuid: str) -> str:
    get_db().expire_all()
    return get_db().query(Alert).filter(Alert.uuid == alert_uuid).one().version


def _comment_text(comment_id: int) -> str:
    get_db().expire_all()
    return get_db().query(Comment).filter(Comment.comment_id == comment_id).one().comment


class TestUpdateAlertComment:
    """Test the PATCH /alerts/{alert_uuid}/comments/{comment_id} endpoint."""

    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        response = await unauth_client.patch(f"/alerts/{VALID_UUID}/comments/1", json={"comment": "x"})
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_requires_alert_write(self, noperm_client: AsyncClient):
        response = await noperm_client.patch(f"/alerts/{VALID_UUID}/comments/1", json={"comment": "x"})
        assert response.status_code == 403

    @pytest.mark.asyncio
    @patch("aceapi_v2.alerts.service.submit_index_task", wraps=submit_index_task)
    async def test_update_comment(self, mock_submit_index_task, client: AsyncClient, client_actor,
                                  caplog: pytest.LogCaptureFixture):
        caplog.set_level(logging.INFO)
        user_id = _unittest_user_id()
        alert_uuid, comment_id = _insert_commented_alert(user_id)
        version = _alert_version(alert_uuid)

        response = await client.patch(
            f"/alerts/{alert_uuid}/comments/{comment_id}", json={"comment": "  edited comment\n"})
        assert response.status_code == 200
        data = response.json()
        assert data["comment_id"] == comment_id
        assert data["alert_uuid"] == alert_uuid
        assert data["user_id"] == user_id
        assert data["comment"] == "edited comment"

        assert _comment_text(comment_id) == "edited comment"
        audit = audit_record(caplog, f"user unittest edited comment {comment_id} on alert {alert_uuid}")
        assert (*audit_actor_of(audit), audit.alert_uuid, audit.comment_id) == (*client_actor, alert_uuid, comment_id)
        # the change is visible to clients polling the alert, and the search index picks it up
        assert _alert_version(alert_uuid) != version
        mock_submit_index_task.assert_called_once_with(alert_uuid)

    @pytest.mark.asyncio
    @patch("aceapi_v2.alerts.service.submit_index_task", wraps=submit_index_task)
    async def test_unchanged_comment_is_not_a_change(self, mock_submit_index_task, client: AsyncClient):
        alert_uuid, comment_id = _insert_commented_alert(_unittest_user_id())
        version = _alert_version(alert_uuid)

        response = await client.patch(
            f"/alerts/{alert_uuid}/comments/{comment_id}", json={"comment": "original comment"})
        assert response.status_code == 200
        assert _alert_version(alert_uuid) == version
        mock_submit_index_task.assert_not_called()

    @pytest.mark.asyncio
    @patch("aceapi_v2.alerts.service.submit_index_task", wraps=submit_index_task)
    async def test_line_endings_alone_are_not_a_change(self, mock_submit_index_task, client: AsyncClient):
        # the GUI's add form stores CRLF; the edit modal's textarea sends LF
        alert_uuid, comment_id = _insert_commented_alert(_unittest_user_id(), "first line\r\nsecond line")
        version = _alert_version(alert_uuid)

        response = await client.patch(
            f"/alerts/{alert_uuid}/comments/{comment_id}", json={"comment": "first line\nsecond line"})
        assert response.status_code == 200
        assert _alert_version(alert_uuid) == version
        assert _comment_text(comment_id) == "first line\r\nsecond line"
        mock_submit_index_task.assert_not_called()

    @pytest.mark.asyncio
    async def test_author_only(self, client: AsyncClient):
        other = User(username=f"comment_author_{uuid4().hex[:8]}", email=f"{uuid4().hex[:8]}@test.com",
                     display_name="Other User", password="pw")
        get_db().add(other)
        get_db().commit()
        alert_uuid, comment_id = _insert_commented_alert(other.id, "other's comment")

        response = await client.patch(
            f"/alerts/{alert_uuid}/comments/{comment_id}", json={"comment": "trying to edit"})
        assert response.status_code == 403
        assert _comment_text(comment_id) == "other's comment"

    @pytest.mark.asyncio
    async def test_comment_on_another_alert(self, client: AsyncClient):
        _, comment_id = _insert_commented_alert(_unittest_user_id())
        other_alert_uuid, _ = _insert_commented_alert(_unittest_user_id())

        response = await client.patch(
            f"/alerts/{other_alert_uuid}/comments/{comment_id}", json={"comment": "edited"})
        assert response.status_code == 404
        assert _comment_text(comment_id) == "original comment"

    @pytest.mark.asyncio
    async def test_unknown_comment(self, client: AsyncClient):
        response = await client.patch(f"/alerts/{VALID_UUID}/comments/999999999", json={"comment": "x"})
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_invalid_uuid(self, client: AsyncClient):
        response = await client.patch("/alerts/not-a-uuid/comments/1", json={"comment": "x"})
        assert response.status_code == 400

    @pytest.mark.asyncio
    @pytest.mark.parametrize("text", ["", "   \n"])
    async def test_empty_comment_rejected(self, client: AsyncClient, text: str):
        alert_uuid, comment_id = _insert_commented_alert(_unittest_user_id())

        response = await client.patch(f"/alerts/{alert_uuid}/comments/{comment_id}", json={"comment": text})
        assert response.status_code == 422
        assert _comment_text(comment_id) == "original comment"
