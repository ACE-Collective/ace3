"""/api/v2/svs/samples: the YARA samples SVS captured and their labels (docs/SVS_API.md, *Samples*)."""

import collections
import csv
import io
import json
import uuid
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.application import app
from aceapi_v2.svs.samples import service
from saq.cas import get_cas
from saq.configuration.config import get_config
from saq.database.model import Alert, DetectionPoint, SVSYaraCapture, User
from saq.database.pool import get_db
from saq.database.private_session import private_transaction
from saq.detection_verdicts.store import clear_verdict, set_verdict
from saq.signatures.builtin import SIGNATURE_VERSION_UNKNOWN
from saq.svs.constants import CaptureState, MissingReason
from saq.yara_scanning.match_record import serialize_match_record, summarize_match_record
from tests.aceapi_v2.conftest import api_key_client, make_api_key
from tests.saq.svs.conftest import (
    OTHER_RULE_UUID,
    RULE_UUID,
    graded_alert,
    insert_capture,
    scan_result,
    set_disposition,
)

pytestmark = pytest.mark.integration

LONG_AGO = datetime(2020, 1, 1)
MISSING_SHA256 = "dd" * 32


def _user_id() -> int:
    return get_db().query(User.id).filter(User.username == "unittest").scalar()


def _store(alert_uuid: str, sha256: str, rule_uuid: str = RULE_UUID, *, content: bytes | None = None,
           record: bool = True, **values) -> int:
    """Put the file (when given) and a match record in the pool and point a capture row at them."""
    pool = get_cas().pool("svs_samples")
    if content is not None:
        pool.put(content, digest=sha256)
    if record:
        match = scan_result(rule_uuid=rule_uuid)
        values.update(record_digest=pool.put(serialize_match_record(match)),
                      match_summary=json.dumps(summarize_match_record(match)))
    return insert_capture(alert_uuid, sha256, rule_uuid, **values)


def _sample(disposition: str, rules: list[str], name: str = "invoice.doc", content: bytes | None = None,
            store: bool = True):
    """A graded alert with one file the rules matched, captured with its bytes and records.
    Returns (alert, sha256, the file's bytes)."""
    content = content or f"sample {uuid.uuid4()}".encode()
    alert, files = graded_alert(disposition, {name: rules}, capture=False, contents={name: content})
    sha256 = files[name].value.lower()
    for rule_uuid in rules:
        _store(alert.uuid, sha256, rule_uuid, content=content if store else None, file_path=name,
               file_size=len(content))
    return alert, sha256, content


async def _get(client: AsyncClient, *filters: str, **params) -> list[dict]:
    response = await client.get("/svs/samples/", params={"f": list(filters), **params})
    assert response.status_code == 200, response.text
    return response.json()["data"]


async def _all_pages(client: AsyncClient, params: dict, limit: int) -> list[dict]:
    rows, cursor = [], None
    for _ in range(100):
        page_params = dict(params, limit=limit)
        if cursor:
            page_params["cursor"] = cursor
        response = await client.get("/svs/samples/", params=page_params)
        assert response.status_code == 200, response.text
        body = response.json()
        rows.extend(body["data"])
        cursor = body["next_cursor"]
        if cursor is None:
            return rows
    raise AssertionError("pagination did not terminate")


def _keys(rows: list[dict]) -> list[tuple[str, str]]:
    return [(row["sha256"], row["rule_uuid"]) for row in rows]


def _open_zip(content: bytes) -> tuple[zipfile.ZipFile, dict]:
    archive = zipfile.ZipFile(io.BytesIO(content))
    archive.setpassword(b"infected")
    manifest_name = next(name for name in archive.namelist() if name.endswith("/manifest.json"))
    return archive, json.loads(archive.read(manifest_name))


#
# access
#

class TestAccess:
    READ_PATHS = ("/svs/samples/", "/svs/samples/export/ndjson", "/svs/samples/export/csv", "/svs/samples/missing",
                  "/svs/samples/captures/1/record", f"/svs/samples/{'ab' * 32}/{RULE_UUID}")
    DOWNLOAD_PATHS = ("/svs/samples/download", f"/svs/samples/{'ab' * 32}/{RULE_UUID}/download")

    @pytest.mark.asyncio
    async def test_requires_auth(self, unauth_client: AsyncClient):
        for path in self.READ_PATHS + self.DOWNLOAD_PATHS:
            assert (await unauth_client.get(path)).status_code == 401, path

    @pytest.mark.asyncio
    async def test_requires_signature_read(self, noperm_client: AsyncClient):
        for path in self.READ_PATHS + self.DOWNLOAD_PATHS:
            assert (await noperm_client.get(path)).status_code == 403, path

    @pytest.mark.asyncio
    async def test_reading_is_not_downloading(self, _override_db_session, session: AsyncSession, test_user):
        _, sha256, _ = _sample("FALSE_POSITIVE", [RULE_UUID])
        key = await make_api_key(session, test_user.id, inherit=False, scope=[("signature", "read")])
        async with api_key_client(key) as client:
            assert (await client.get("/svs/samples/")).status_code == 200
            assert (await client.get(f"/svs/samples/{sha256}/{RULE_UUID}")).status_code == 200
            assert (await client.get(f"/svs/samples/{sha256}/{RULE_UUID}/download")).status_code == 403
            assert (await client.get("/svs/samples/download")).status_code == 403

    @pytest.mark.asyncio
    async def test_alert_read_alone_is_not_enough(self, _override_db_session, session: AsyncSession, test_user):
        key = await make_api_key(session, test_user.id, inherit=False, scope=[("alert", "read")])
        async with api_key_client(key) as client:
            assert (await client.get("/svs/samples/")).status_code == 403
            assert (await client.get("/filter-screens/svs_samples")).status_code == 403


#
# rows
#

@pytest.mark.asyncio
async def test_rows_carry_the_label_and_counts(client: AsyncClient):
    alert, sha256, content = _sample("DELIVERY", [RULE_UUID, OTHER_RULE_UUID])
    rows = {row["rule_uuid"]: row for row in await _get(client)}
    assert set(rows) == {RULE_UUID, OTHER_RULE_UUID}

    row = rows[RULE_UUID]
    assert row["sha256"] == sha256
    assert (row["label"], row["label_source"]) == ("tp", "inherited_multi")
    assert row["votes"]["tp_inherited_multi"] == 1
    assert (row["capture_count"], row["stored"], row["missing"], row["missing_data"]) == (1, 1, 0, 0)
    assert (row["file_path"], row["file_size"], row["namespace"]) == ("invoice.doc", len(content), "unittest")
    assert row["local"] is True


#
# keyset paging
#

class TestKeysetPaging:
    @pytest.fixture
    def corpus(self):
        """Seven samples, three of them captured at the same moment, with differing labels."""
        moment = datetime.now().replace(microsecond=0) - timedelta(hours=1)
        for index in range(3):
            insert_capture(str(uuid.uuid4()), f"{index:x}" * 64, created_at=moment, rule_name=f"tie_{index}")
        for index in range(3, 6):
            insert_capture(str(uuid.uuid4()), f"{index:x}" * 64, created_at=moment - timedelta(minutes=index),
                           rule_name="rule_b" if index % 2 else "rule_a")
        _sample("FALSE_POSITIVE", [RULE_UUID])

    @pytest.mark.asyncio
    @pytest.mark.parametrize("sort", ["last_captured", "first_captured", "capture_count", "rule", "label", "sha256"])
    @pytest.mark.parametrize("desc", [False, True])
    async def test_every_sort_pages_without_skip_or_repeat(self, client: AsyncClient, corpus, sort, desc):
        params = {"sort": sort, "desc": str(desc).lower()}
        everything = await _get(client, **params, limit=100)
        assert len(everything) == 7
        assert _keys(await _all_pages(client, params, 2)) == _keys(everything)

    @pytest.mark.asyncio
    async def test_inserts_between_pages_are_not_repeated(self, client: AsyncClient, corpus):
        first = (await client.get("/svs/samples/", params={"limit": 3})).json()
        _sample("DELIVERY", [RULE_UUID])
        rest = await _all_pages(client, {"cursor": first["next_cursor"]}, 3)
        seen = _keys(first["data"]) + _keys(rest)
        assert len(seen) == len(set(seen)) == 7

    @pytest.mark.asyncio
    async def test_a_cursor_belongs_to_its_order(self, client: AsyncClient, corpus):
        cursor = (await client.get("/svs/samples/", params={"limit": 2, "sort": "rule"})).json()["next_cursor"]
        assert (await client.get("/svs/samples/", params={"cursor": cursor, "sort": "rule"})).status_code == 200
        assert (await client.get("/svs/samples/", params={"cursor": cursor, "sort": "label"})).status_code == 400
        assert (await client.get("/svs/samples/", params={
            "cursor": cursor, "sort": "rule", "desc": "false"})).status_code == 400
        assert (await client.get("/svs/samples/", params={"cursor": "garbage"})).status_code == 400

    @pytest.mark.asyncio
    async def test_limits(self, client: AsyncClient):
        assert (await client.get("/svs/samples/", params={"limit": 0})).status_code == 422
        assert (await client.get("/svs/samples/", params={"limit": 1001})).status_code == 422
        assert (await client.get("/svs/samples/", params={"sort": "nope"})).status_code == 422


#
# filters
#

class TestFilters:
    @pytest.fixture
    def samples(self) -> dict:
        """fp: an FP alert's file. tp: a TP alert's file, matched by two rules (two samples). none:
        a REVIEWED alert's file. missing: an old capture whose file was gone, with an unknown
        version."""
        fp_alert, fp, _ = _sample("FALSE_POSITIVE", [RULE_UUID], name="fp.doc")
        tp_alert, tp, _ = _sample("DELIVERY", [RULE_UUID, OTHER_RULE_UUID], name="dir/tp.exe")
        _, none, _ = _sample("REVIEWED", [OTHER_RULE_UUID], name="none.js")
        insert_capture(str(uuid.uuid4()), MISSING_SHA256, rule_name="old_rule", file_path="gone.bin",
                       created_at=datetime.now() - timedelta(days=30), state=CaptureState.MISSING,
                       missing_reason=MissingReason.FILE, signature_version=SIGNATURE_VERSION_UNKNOWN,
                       stored_at=None)
        return {"names": {(fp, RULE_UUID): "fp", (tp, RULE_UUID): "tp", (tp, OTHER_RULE_UUID): "tp2",
                          (none, OTHER_RULE_UUID): "none", (MISSING_SHA256, RULE_UUID): "missing"},
                "fp_alert": fp_alert, "tp_alert": tp_alert, "tp": tp}

    @staticmethod
    def _names(rows: list[dict], samples: dict) -> list[str]:
        return sorted(samples["names"][key] for key in _keys(rows))

    @pytest.mark.asyncio
    @pytest.mark.parametrize("filters, expected", [
        ([], ["fp", "missing", "none", "tp", "tp2"]),
        (["signature:" + OTHER_RULE_UUID], ["none", "tp2"]),
        (["rule:old"], ["missing"]),
        (["file_name:tp.exe"], ["tp", "tp2"]),
        (["file_name:%"], []),
        (["label:fp"], ["fp"]),
        (["label:tp,fp"], ["fp", "tp", "tp2"]),
        (["label:none"], ["missing", "none"]),
        # an inverse keeps the rows whose value is null
        (["!label:tp"], ["fp", "missing", "none"]),
        (["label_source:inherited_multi"], ["tp", "tp2"]),
        (["!label_source:inherited_multi"], ["fp", "missing", "none"]),
        (["last_captured:-7d"], ["fp", "none", "tp", "tp2"]),
        (["stored:false"], ["missing"]),
        (["missing_data:true"], ["missing"]),
        (["unknown_version:true"], ["missing"]),
        (["!unknown_version:true"], ["fp", "none", "tp", "tp2"]),
        # repeats of one filter are ORed, different filters ANDed
        (["label:tp", "label:fp", "signature:" + RULE_UUID], ["fp", "tp"]),
    ])
    async def test_filters(self, client: AsyncClient, samples, filters, expected):
        assert self._names(await _get(client, *filters), samples) == expected

    @pytest.mark.asyncio
    async def test_by_sha256_and_alert(self, client: AsyncClient, samples):
        assert self._names(await _get(client, f"sha256:{samples['tp'].upper()}"), samples) == ["tp", "tp2"]
        assert self._names(await _get(client, f"alert:{samples['fp_alert'].uuid}"), samples) == ["fp"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("filter_param", [
        "nope:x", "label:maybe", "label_source:inherited", "last_captured:soon", "sha256:abc",
        "alert:not-a-uuid", "stored:yes", "signature:a b"])
    async def test_bad_filters_are_422(self, client: AsyncClient, filter_param):
        response = await client.get("/svs/samples/", params={"f": filter_param})
        assert response.status_code == 422, filter_param


#
# incremental pulls
#

@pytest.mark.asyncio
async def test_changed_since(client: AsyncClient):
    a_alert, a, _ = _sample("DELIVERY", [RULE_UUID, OTHER_RULE_UUID])
    b_alert, b, _ = _sample("DELIVERY", [RULE_UUID])
    get_db().execute(update(Alert).values(updated_at=LONG_AGO))
    get_db().commit()
    with private_transaction() as private:
        private.execute(update(SVSYaraCapture).values(updated_at=LONG_AGO))

    since = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    assert await _get(client, changed_since=since) == []

    # setting and clearing a verdict both show up; the cleared verdict leaves only history
    content_hash = get_db().query(DetectionPoint.content_hash).filter(
        DetectionPoint.alert_id == a_alert.id, DetectionPoint.signature_uuid == RULE_UUID).scalar()
    set_verdict(a_alert.id, content_hash, "fp", _user_id())
    clear_verdict(a_alert.id, content_hash, _user_id())
    assert _keys(await _get(client, changed_since=since)) == [(a, RULE_UUID)]

    # a disposition change relabels every sample of the alert
    set_disposition(b_alert.uuid, "FALSE_POSITIVE")
    assert sorted(_keys(await _get(client, changed_since=since))) == sorted([(a, RULE_UUID), (b, RULE_UUID)])

    # a new capture
    _, c, _ = _sample("REVIEWED", [RULE_UUID])
    assert (c, RULE_UUID) in _keys(await _get(client, changed_since=since))


#
# exports
#

class TestExport:
    @pytest.mark.asyncio
    async def test_ndjson(self, client: AsyncClient, monkeypatch):
        monkeypatch.setattr(service, "LISTING_EXPORT_PAGE_SIZE", 2)
        for _ in range(3):
            _sample("FALSE_POSITIVE", [RULE_UUID])

        response = await client.get("/svs/samples/export/ndjson", params={"f": "label:fp"})
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/x-ndjson")
        lines = [json.loads(line) for line in response.text.splitlines()]
        assert len(lines) == 3 and {line["label"] for line in lines} == {"fp"}

    @pytest.mark.asyncio
    async def test_csv(self, client: AsyncClient, monkeypatch):
        monkeypatch.setattr(service, "LISTING_EXPORT_PAGE_SIZE", 2)
        for _ in range(3):
            _sample("REVIEWED", [RULE_UUID])

        response = await client.get("/svs/samples/export/csv")
        assert response.status_code == 200
        records = list(csv.DictReader(io.StringIO(response.text)))
        assert len(records) == 3
        assert {r["label"] for r in records} == {""}
        assert {r["fp_inherited_single"] for r in records} == {"0"}
        assert "votes" not in records[0]

    @pytest.mark.asyncio
    async def test_a_bad_filter_is_422_before_the_stream_starts(self, client: AsyncClient):
        assert (await client.get("/svs/samples/export/csv", params={"f": "nope:x"})).status_code == 422

    def test_each_export_documents_exactly_one_media_type(self):
        paths = app.openapi()["paths"]
        for path, media_type in (("/svs/samples/export/ndjson", "application/x-ndjson"),
                                 ("/svs/samples/export/csv", "text/csv")):
            assert list(paths[path]["get"]["responses"]["200"]["content"]) == [media_type]


#
# one sample
#

class TestDetail:
    @pytest.mark.asyncio
    async def test_the_sample_its_captures_and_their_verdicts(self, client: AsyncClient):
        content = f"detail {uuid.uuid4()}".encode()
        first, sha256, _ = _sample("FALSE_POSITIVE", [RULE_UUID], content=content)
        second, _, _ = _sample("DELIVERY", [RULE_UUID], content=content, name="other.doc")
        orphan = insert_capture(str(uuid.uuid4()), sha256)

        response = await client.get(f"/svs/samples/{sha256.upper()}/{RULE_UUID}")
        assert response.status_code == 200, response.text
        sample = response.json()
        assert (sample["label"], sample["label_source"]) == ("conflicted", "inherited_single")
        assert sample["capture_count"] == 3
        assert [capture["id"] for capture in sample["captures"]][0] == orphan

        captures = {capture["alert_uuid"]: capture for capture in sample["captures"]}
        (detection,) = captures[first.uuid]["detections"]
        assert (detection["verdict"], detection["verdict_source"]) == ("fp", "inherited_single")
        (detection,) = captures[second.uuid]["detections"]
        assert (detection["verdict"], detection["verdict_source"]) == ("tp", "inherited_single")
        assert captures[second.uuid]["file_path"] == "other.doc"
        assert captures[second.uuid]["has_record"] is True
        assert captures[second.uuid]["match_summary"]["meta"]["uuid"] == RULE_UUID
        assert sample["captures"][0]["detections"] == []

    @pytest.mark.asyncio
    async def test_not_found_and_bad_keys(self, client: AsyncClient):
        assert (await client.get(f"/svs/samples/{'ab' * 32}/{RULE_UUID}")).status_code == 404
        assert (await client.get(f"/svs/samples/abc/{RULE_UUID}")).status_code == 400
        assert (await client.get(f"/svs/samples/{'ab' * 32}/bad%20uuid")).status_code == 400

    @pytest.mark.asyncio
    async def test_the_match_record(self, client: AsyncClient):
        alert, sha256, _ = _sample("FALSE_POSITIVE", [RULE_UUID])
        (capture,) = (await client.get(f"/svs/samples/{sha256}/{RULE_UUID}")).json()["captures"]

        response = await client.get(f"/svs/samples/captures/{capture['id']}/record")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["content-disposition"].startswith("inline")
        assert response.json()["meta"]["uuid"] == RULE_UUID

        without = _store(alert.uuid, "ee" * 32, record=False)
        assert (await client.get(f"/svs/samples/captures/{without}/record")).status_code == 404
        assert (await client.get("/svs/samples/captures/999999999/record")).status_code == 404

    @pytest.mark.asyncio
    async def test_a_record_on_another_node_is_wrong_node(self, client: AsyncClient):
        alert, _, _ = _sample("FALSE_POSITIVE", [RULE_UUID])
        elsewhere = _store(alert.uuid, "ee" * 32, node="some-other-node")
        response = await client.get(f"/svs/samples/captures/{elsewhere}/record")
        assert response.status_code == 409
        assert response.json()["detail"]["error"] == "wrong_node"
        assert response.json()["detail"]["node"] == "some-other-node"


@pytest.mark.asyncio
async def test_missing_summary(client: AsyncClient):
    insert_capture(str(uuid.uuid4()), MISSING_SHA256, state=CaptureState.MISSING, missing_reason=MissingReason.FILE)
    _sample("FALSE_POSITIVE", [RULE_UUID])
    response = await client.get("/svs/samples/missing")
    assert response.status_code == 200
    assert response.json() == [{"rule_uuid": RULE_UUID, "rule_name": "svs_rule", "reason": "file", "count": 1}]


#
# downloads
#

class TestDownload:
    @pytest.mark.asyncio
    async def test_one_sample(self, client: AsyncClient):
        content = f"download {uuid.uuid4()}".encode()
        first, sha256, _ = _sample("FALSE_POSITIVE", [RULE_UUID], name="dir/manifest.json", content=content)
        _sample("DELIVERY", [RULE_UUID], content=content)

        response = await client.get(f"/svs/samples/{sha256}/{RULE_UUID}/download")
        assert response.status_code == 200, response.text
        assert response.headers["content-type"] == "application/zip"
        archive, manifest = _open_zip(response.content)
        (entry,) = manifest["files"]
        assert entry["sha256"] == sha256 and manifest["skipped"] == []
        # the file once, under a name that cannot be the manifest's
        assert archive.read(f"svs-sample-{sha256}/{entry['path']}") == content
        (sample,) = entry["samples"]
        assert (sample["rule_uuid"], sample["label"]) == (RULE_UUID, "conflicted")
        records = [capture["match_record"] for capture in sample["captures"]]
        assert len(records) == 2 and all(records)
        for path in records:
            assert json.loads(archive.read(f"svs-sample-{sha256}/{path}"))["meta"]["uuid"] == RULE_UUID

    @pytest.mark.asyncio
    async def test_a_sample_without_its_file(self, client: AsyncClient):
        _, sha256, _ = _sample("FALSE_POSITIVE", [RULE_UUID])
        insert_capture(str(uuid.uuid4()), MISSING_SHA256, state=CaptureState.MISSING, missing_reason=MissingReason.FILE)
        assert (await client.get(f"/svs/samples/{MISSING_SHA256}/{RULE_UUID}/download")).status_code == 404
        assert (await client.get(f"/svs/samples/{'ab' * 32}/{RULE_UUID}/download")).status_code == 404

    @pytest.mark.asyncio
    async def test_a_file_on_another_node_is_wrong_node(self, client: AsyncClient):
        alert, _, _ = _sample("FALSE_POSITIVE", [RULE_UUID])
        insert_capture(alert.uuid, "ee" * 32, node="some-other-node")
        response = await client.get(f"/svs/samples/{'ee' * 32}/{RULE_UUID}/download")
        assert response.status_code == 409
        assert response.json()["detail"]["error"] == "wrong_node"

    @pytest.mark.asyncio
    async def test_bulk(self, client: AsyncClient):
        _, fp, fp_content = _sample("FALSE_POSITIVE", [RULE_UUID])
        _, tp, tp_content = _sample("DELIVERY", [RULE_UUID, OTHER_RULE_UUID])
        alert, _, _ = _sample("REVIEWED", [RULE_UUID])
        insert_capture(alert.uuid, "ee" * 32, node="some-other-node")

        response = await client.get("/svs/samples/download", params={"f": "label:tp,fp"})
        assert response.status_code == 200, response.text
        archive, manifest = _open_zip(response.content)
        files = {entry["sha256"]: entry for entry in manifest["files"]}
        assert set(files) == {fp, tp}
        assert archive.read(f"svs-samples/{files[fp]['path']}") == fp_content
        # a file two rules matched is in the zip once, with both samples
        assert archive.read(f"svs-samples/{files[tp]['path']}") == tp_content
        assert {sample["rule_uuid"] for sample in files[tp]["samples"]} == {RULE_UUID, OTHER_RULE_UUID}

        # files on another node's local pool are listed as skipped
        _, manifest = _open_zip((await client.get("/svs/samples/download")).content)
        assert [(entry["sha256"], entry["reason"]) for entry in manifest["skipped"]] == [("ee" * 32, "wrong_node")]

    @pytest.mark.asyncio
    async def test_bulk_limits(self, client: AsyncClient, monkeypatch):
        for _ in range(3):
            _sample("FALSE_POSITIVE", [RULE_UUID])
        config = get_config().svs.samples
        monkeypatch.setattr(config, "max_bulk_download_files", 2)
        assert (await client.get("/svs/samples/download")).status_code == 413

        monkeypatch.setattr(config, "max_bulk_download_files", 10)
        monkeypatch.setattr(config, "max_bulk_download_bytes", 10)
        assert (await client.get("/svs/samples/download")).status_code == 413

    @pytest.mark.asyncio
    async def test_bulk_errors(self, client: AsyncClient):
        assert (await client.get("/svs/samples/download")).status_code == 404
        assert (await client.get("/svs/samples/download", params={"f": "nope:x"})).status_code == 422

        alert, _, _ = _sample("FALSE_POSITIVE", [RULE_UUID], store=False)
        get_db().execute(update(Alert).where(Alert.id == alert.id).values(updated_at=LONG_AGO))
        get_db().commit()
        with private_transaction() as private:
            private.execute(update(SVSYaraCapture).values(node="some-other-node"))
        response = await client.get("/svs/samples/download")
        assert response.status_code == 409


#
# docs/SVS_API.md
#

@pytest.mark.asyncio
async def test_worked_example_conflicted_samples_per_rule(client: AsyncClient):
    """docs/SVS_API.md, *Conflicted samples per rule*, run against the API."""
    for rules in ([RULE_UUID], [RULE_UUID, OTHER_RULE_UUID]):
        content = f"example {uuid.uuid4()}".encode()
        _sample("DELIVERY", rules, content=content)
        _sample("FALSE_POSITIVE", rules, content=content, name="again.doc")
    _sample("FALSE_POSITIVE", [OTHER_RULE_UUID])

    conflicted = collections.Counter()
    params = {"f": ["label:conflicted"], "limit": 1000}
    while True:
        page = (await client.get("/svs/samples/", params=params)).json()
        for row in page["data"]:
            conflicted[row["rule_name"]] += 1
        if page["next_cursor"] is None:
            break
        params["cursor"] = page["next_cursor"]

    # the TP alert where both rules fired is inherited_multi, which the FP alert outweighs
    assert conflicted == {"svs_rule": 1}
