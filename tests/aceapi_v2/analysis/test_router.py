"""POST /api/v2/analysis/: submitting analysis to this node (ace_api.submit())."""

import hashlib
import json
import os
from datetime import datetime

import pytest
import pytz
from httpx import AsyncClient

from saq.analysis.root import KEY_PLAYBOOK_URL, RootAnalysis
from saq.constants import (
    ANALYSIS_MODE_CORRELATION,
    DIRECTIVE_NO_SCAN,
    EVENT_TIME_FORMAT_JSON_TZ,
    F_FILE,
    F_IP,
    F_USER,
    NODE_STATUS_DRAINING,
    NODE_STATUS_RUNNING,
)
from saq.database.model import Alert
from saq.database.pool import get_db, get_db_connection
from saq.database.util.node import set_node_status
from saq.environment import get_data_dir, get_global_runtime_settings, get_local_timezone
from saq.json_encoding import _JSONEncoder
from saq.util.uuid import get_storage_dir

pytestmark = pytest.mark.integration

EVENT_TIME = get_local_timezone().localize(
    datetime(2017, 11, 11, hour=7, minute=36, second=1, microsecond=1)).astimezone(pytz.UTC).strftime(EVENT_TIME_FORMAT_JSON_TZ)
EVENT_TIME_JSON = "2017-11-11T07:36:01.000001+0000"


def _submission(**overrides) -> dict:
    submission = {
        "analysis_mode": "analysis",
        "tool": "unittest",
        "tool_instance": "unittest_instance",
        "type": "unittest",
        "description": "testing",
        "event_time": EVENT_TIME,
        "details": {"hello": "world"},
        "observables": [
            {"type": F_IP, "value": "1.2.3.4", "time": EVENT_TIME, "tags": ["tag_1", "tag_2"],
             "directives": [DIRECTIVE_NO_SCAN], "limited_analysis": ["basic_test"]},
            {"type": F_USER, "value": "test_user", "time": EVENT_TIME},
        ],
        "tags": ["alert_tag_1", "alert_tag_2"],
        "queue": "default",
        "instructions": "Test instructions.",
        "extensions": {KEY_PLAYBOOK_URL: "http://playbook"},
    }
    submission.update(overrides)
    return submission


async def _submit(client: AsyncClient, submission: dict, files: list[tuple[str, bytes]] = ()):
    return await client.post(
        "/analysis/",
        data={"analysis": json.dumps(submission, cls=_JSONEncoder)},
        files=[("file", (name, content, "application/octet-stream")) for name, content in files] or None)


def _load(root_uuid: str) -> RootAnalysis:
    root = RootAnalysis(storage_dir=get_storage_dir(root_uuid))
    root.load()
    return root


def _as_json(value) -> dict:
    """The JSON form the API serves, so that datetimes compare as the strings clients see."""
    return json.loads(json.dumps(value, cls=_JSONEncoder))


def _stored_roots() -> int:
    node_dir = os.path.join(get_data_dir(), get_global_runtime_settings().saq_node)
    if not os.path.isdir(node_dir):
        return 0
    return sum(len(os.listdir(os.path.join(node_dir, subdir))) for subdir in os.listdir(node_dir))


class TestSubmit:
    @pytest.mark.asyncio
    async def test_the_root_with_its_observables_and_files(self, client: AsyncClient):
        response = await _submit(client, _submission(), [("sample.dat", b"Hello, world!")])

        assert response.status_code == 201
        uuid = response.json()["uuid"]
        root = _load(uuid)
        stored = _as_json(root.json)
        assert {key: stored[key] for key in ("analysis_mode", "tool", "tool_instance", "type", "description", "queue",
                                             "instructions", "extensions", "event_time")} == {
            "analysis_mode": "analysis", "tool": "unittest", "tool_instance": "unittest_instance", "type": "unittest",
            "description": "testing", "queue": "default", "instructions": "Test instructions.",
            "extensions": {KEY_PLAYBOOK_URL: "http://playbook"}, "event_time": EVENT_TIME_JSON}
        assert stored["tags"][:2] == ["alert_tag_1", "alert_tag_2"]

        observables = {o["type"]: o for o in stored["observable_store"].values()}
        assert set(observables) == {F_IP, F_USER, F_FILE}
        ip = observables[F_IP]
        assert (ip["value"], ip["time"], ip["tags"], ip["directives"], ip["limited_analysis"]) == (
            "1.2.3.4", EVENT_TIME_JSON, ["tag_1", "tag_2"], [DIRECTIVE_NO_SCAN], ["basic_test"])
        assert (observables[F_USER]["value"], observables[F_USER]["time"]) == ("test_user", EVENT_TIME_JSON)
        assert observables[F_FILE]["file_path"] == "sample.dat"
        with open(root.get_observable(observables[F_FILE]["uuid"]).full_path, "rb") as fp:
            assert fp.read() == b"Hello, world!"

        root.load_details()
        assert root.details == {"hello": "world"}

        # queued on this node, in its analysis mode
        with get_db_connection() as db:
            cursor = db.cursor()
            cursor.execute("SELECT node_id, analysis_mode FROM workload WHERE uuid = %s", (uuid,))
            assert cursor.fetchone() == (get_global_runtime_settings().saq_node_id, "analysis")

        # the submission is recorded as it was received
        submission = _as_json(root.submission)
        assert submission["description"] == "testing"
        assert len(submission["observables"]) == 2
        assert submission["files"][0].endswith("files/sample.dat")

    @pytest.mark.asyncio
    async def test_added_by_is_kept(self, client: AsyncClient):
        added_time = get_local_timezone().localize(datetime(2026, 6, 11, hour=9, minute=30)).astimezone(pytz.UTC).strftime(EVENT_TIME_FORMAT_JSON_TZ)
        file_sha256 = hashlib.sha256(b"Hello, world!").hexdigest()
        response = await _submit(client, _submission(observables=[
            {"type": F_IP, "value": "1.2.3.4", "added_by": "analyst1", "added_time": added_time},
            {"type": F_USER, "value": "test_user"},
            {"type": F_FILE, "value": file_sha256, "file_path": "sample.dat", "added_by": "analyst1", "added_time": added_time},
        ]), [("sample.dat", b"Hello, world!")])

        stored = _as_json(_load(response.json()["uuid"]).json)
        for observable in stored["observable_store"].values():
            if observable["type"] in (F_IP, F_FILE):
                assert (observable["added_by"], observable["added_time"]) == ("analyst1", "2026-06-11T09:30:00.000000+0000")
            else:
                assert (observable["added_by"], observable["added_time"]) == (None, None)

    @pytest.mark.asyncio
    async def test_the_queue(self, client: AsyncClient):
        response = await _submit(client, _submission(queue="internal"))

        assert _load(response.json()["uuid"]).queue == "internal"

    @pytest.mark.asyncio
    async def test_correlation_mode_is_an_alert(self, client: AsyncClient):
        response = await _submit(client, _submission(analysis_mode=ANALYSIS_MODE_CORRELATION))

        assert response.status_code == 201
        get_db().close()
        alert = get_db().query(Alert).filter(Alert.uuid == response.json()["uuid"]).one()
        assert alert.description == "testing"

    @pytest.mark.asyncio
    async def test_no_event_time_is_now(self, client: AsyncClient):
        """A null event time used to be a 500."""
        before = datetime.now(pytz.utc)
        response = await _submit(client, _submission(event_time=None))

        assert response.status_code == 201
        assert _load(response.json()["uuid"]).event_time >= before.replace(microsecond=0)

    @pytest.mark.asyncio
    async def test_without_files_as_a_plain_form(self, client: AsyncClient):
        """ace_api.submit() with no files sends a urlencoded form rather than multipart."""
        response = await client.post("/analysis/", data={"analysis": json.dumps(_submission(), cls=_JSONEncoder)})

        assert response.status_code == 201


class TestInvalid:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("submission, status, detail", [
        (_submission(company_name="invalid_company_name"), 400,
         "wrong company invalid_company_name (are you sending to the correct system?)"),
        ({key: value for key, value in _submission().items() if key != "description"}, 400,
         "missing description field in submission"),
        (_submission(event_time="20189-13-143"), 400, "invalid event time format"),
        (_submission(observables=[{"type": F_IP, "time": EVENT_TIME}]), 400, "invalid observable"),
        (_submission(observables=[{"value": "1.2.3.4"}]), 400, "invalid observable"),
        (_submission(observables=[{"type": F_IP, "value": "1.2.3.4", "time": "INVALID_TIME"}]), 400, "invalid observable"),
    ])
    async def test_refused_and_nothing_is_left_behind(self, client: AsyncClient, submission, status, detail):
        before = _stored_roots()

        response = await _submit(client, submission, [("sample.dat", b"Hello, world!")])

        assert response.status_code == status
        assert response.json()["detail"].startswith(detail)
        assert _stored_roots() == before

    @pytest.mark.asyncio
    async def test_the_analysis_field_is_required(self, client: AsyncClient):
        assert (await client.post("/analysis/", data={})).status_code == 422
        assert (await client.post("/analysis/", data={"analysis": "not json"})).status_code == 422
        assert (await client.post("/analysis/", data={"analysis": "[]"})).status_code == 422

    @pytest.mark.asyncio
    async def test_requires_alert_create(self, noperm_client: AsyncClient):
        assert (await _submit(noperm_client, _submission())).status_code == 403


class TestDraining:
    @pytest.mark.asyncio
    async def test_a_draining_node_refuses_submissions(self, client: AsyncClient):
        node_id = get_global_runtime_settings().saq_node_id
        set_node_status(node_id, NODE_STATUS_DRAINING)
        try:
            assert (await _submit(client, _submission())).status_code == 503
        finally:
            set_node_status(node_id, NODE_STATUS_RUNNING)

        assert (await _submit(client, _submission())).status_code == 201
