"""POST /api/v2/analysis/: submitting analysis to this node (ace_api.submit())."""

import hashlib
import json
import os
import uuid as uuidlib
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
    EventTimeSource,
)
from saq.database.model import Alert
from saq.database.pool import get_db, get_db_connection
from saq.database.util.node import set_node_status
from saq.environment import get_data_dir, get_global_runtime_settings, get_local_timezone
from saq.json_encoding import _JSONEncoder
from saq.util.filesystem import is_path_under
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
        root = _load(response.json()["uuid"])
        assert root.event_time >= before.replace(microsecond=0)
        assert root.event_time_source == EventTimeSource.NOW

    @pytest.mark.asyncio
    async def test_the_event_time_source(self, client: AsyncClient):
        response = await _submit(client, _submission())
        assert _load(response.json()["uuid"]).event_time_source == EventTimeSource.EVENT

        # a hunt run from the command line couldn't extract the event's time
        response = await _submit(client, _submission(event_time_source="query_time"))
        assert _load(response.json()["uuid"]).event_time_source == EventTimeSource.QUERY_TIME

        # without a time there is nothing for it to describe
        response = await _submit(client, _submission(event_time=None, event_time_source="query_time"))
        assert _load(response.json()["uuid"]).event_time_source == EventTimeSource.NOW

    @pytest.mark.asyncio
    async def test_without_files_as_a_plain_form(self, client: AsyncClient):
        """ace_api.submit() with no files sends a urlencoded form rather than multipart."""
        response = await client.post("/analysis/", data={"analysis": json.dumps(_submission(), cls=_JSONEncoder)})

        assert response.status_code == 201


def _file_observables(root: RootAnalysis) -> list:
    return [o for o in root.all_observables if o.type == F_FILE]


class TestUploadNames:
    """The upload's file name is the client's: it may name a subdirectory of the root's files
    directory, but never a place outside it."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("name, stored", [
        ("../../{name}", "_/_/{name}"),
        ("sub/../../{name}", "sub/_/_/{name}"),
        ("..", "_"),
    ])
    async def test_a_name_outside_the_root_is_kept_inside(self, client: AsyncClient, name, stored):
        file_name = f"escaped-{uuidlib.uuid4().hex}.txt"
        name = name.format(name=file_name)
        stored = stored.format(name=file_name)

        response = await _submit(client, _submission(), [(name, b"escaped")])

        assert response.status_code == 201
        root = _load(response.json()["uuid"])
        (file_observable,) = _file_observables(root)
        assert file_observable.file_path == stored
        assert is_path_under(file_observable.full_path, root.file_dir)
        with open(file_observable.full_path, "rb") as fp:
            assert fp.read() == b"escaped"

        assert not os.path.exists(os.path.join(root.file_dir, "..", "..", file_name))

    @pytest.mark.asyncio
    async def test_an_absolute_name_is_kept_inside(self, client: AsyncClient, tmp_path):
        target = tmp_path / "escaped.txt"

        response = await _submit(client, _submission(), [(str(target), b"escaped")])

        assert response.status_code == 201
        root = _load(response.json()["uuid"])
        (file_observable,) = _file_observables(root)
        assert file_observable.file_path == str(target).lstrip("/")
        assert is_path_under(file_observable.full_path, root.file_dir)
        assert not target.exists()

    @pytest.mark.asyncio
    async def test_a_subdirectory_is_kept(self, client: AsyncClient):
        """ace_api's relative_storage_path places a file in a subdirectory of the root."""
        response = await _submit(client, _submission(), [("dest/test.txt", b"content")])

        assert response.status_code == 201
        root = _load(response.json()["uuid"])
        (file_observable,) = _file_observables(root)
        assert file_observable.file_path == "dest/test.txt"
        assert os.path.realpath(file_observable.full_path) == os.path.realpath(os.path.join(root.file_dir, "dest", "test.txt"))
        with open(file_observable.full_path, "rb") as fp:
            assert fp.read() == b"content"

    @pytest.mark.asyncio
    async def test_the_observable_file_path_is_not_used(self, client: AsyncClient):
        """The submission's description of the file names it too; only the upload's own name counts."""
        name = f"escaped-{uuidlib.uuid4().hex}.txt"
        file_sha256 = hashlib.sha256(b"escaped").hexdigest()

        response = await _submit(client, _submission(observables=[
            {"type": F_FILE, "value": file_sha256, "file_path": f"../../{name}", "tags": ["described"]},
        ]), [("upload.txt", b"escaped")])

        assert response.status_code == 201
        root = _load(response.json()["uuid"])
        (file_observable,) = _file_observables(root)
        assert file_observable.file_path == "upload.txt"
        assert file_observable.has_tag("described")
        assert not os.path.exists(os.path.join(root.file_dir, "..", "..", name))

    @pytest.mark.asyncio
    async def test_a_name_with_spaces_and_unicode_is_kept(self, client: AsyncClient):
        response = await _submit(client, _submission(), [("Quarterly Report é.pdf", b"content")])

        assert response.status_code == 201
        (file_observable,) = _file_observables(_load(response.json()["uuid"]))
        assert file_observable.file_path == "Quarterly Report é.pdf"
        with open(file_observable.full_path, "rb") as fp:
            assert fp.read() == b"content"

    @pytest.mark.asyncio
    async def test_an_empty_name(self, client: AsyncClient):
        """httpx leaves an empty file name out, which makes the part a plain field, so the body is
        written out to send filename=""."""
        boundary = "unittestboundary"
        body = (f'--{boundary}\r\nContent-Disposition: form-data; name="analysis"\r\n\r\n'
                f'{json.dumps(_submission(), cls=_JSONEncoder)}\r\n'
                f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename=""\r\n'
                f'Content-Type: application/octet-stream\r\n\r\ncontent\r\n--{boundary}--\r\n').encode()

        response = await client.post("/analysis/", content=body,
                                     headers={"content-type": f"multipart/form-data; boundary={boundary}"})

        assert response.status_code == 201
        (file_observable,) = _file_observables(_load(response.json()["uuid"]))
        assert file_observable.file_path == "upload"


    @pytest.mark.asyncio
    async def test_uploads_with_the_same_name_are_kept_apart(self, client: AsyncClient):
        """Every unnamed upload is stored as "upload", and two files can share a basename. The
        second must not be written over the first, whose hardcopy is the same file."""
        boundary = "unittestboundary"
        parts = "".join(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename=""\r\n'
                        f'Content-Type: application/octet-stream\r\n\r\n{content}\r\n'
                        for content in ("first", "second"))
        body = (f'--{boundary}\r\nContent-Disposition: form-data; name="analysis"\r\n\r\n'
                f'{json.dumps(_submission(), cls=_JSONEncoder)}\r\n{parts}--{boundary}--\r\n').encode()

        response = await client.post("/analysis/", content=body,
                                     headers={"content-type": f"multipart/form-data; boundary={boundary}"})

        assert response.status_code == 201
        file_observables = _file_observables(_load(response.json()["uuid"]))
        assert sorted(o.file_path for o in file_observables) == ["upload", "upload_000"]
        for file_observable in file_observables:
            with open(file_observable.full_path, "rb") as fp:
                assert hashlib.sha256(fp.read()).hexdigest() == file_observable.value
        assert {o.value for o in file_observables} == {hashlib.sha256(c).hexdigest() for c in (b"first", b"second")}


class TestInvalid:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("submission, status, detail", [
        (_submission(company_name="invalid_company_name"), 400,
         "wrong company invalid_company_name (are you sending to the correct system?)"),
        ({key: value for key, value in _submission().items() if key != "description"}, 400,
         "missing description field in submission"),
        (_submission(event_time="20189-13-143"), 400, "invalid event time format"),
        (_submission(event_time_source="unset"), 400, "invalid event_time_source unset"),
        (_submission(event_time_source="sometime"), 400, "invalid event_time_source sometime"),
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
