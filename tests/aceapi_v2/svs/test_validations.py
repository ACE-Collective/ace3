"""/api/v2/svs/yara/validations: the YARA validation queue and its reports (docs/SVS_API.md)."""

import csv
import io
import json
import logging
import uuid
import zipfile

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from aceapi_v2.svs.yara.validations import service
from aceapi_v2.svs.yara.validations.schemas import ValidationRequest
from saq.database.model import User
from saq.database.pool import get_db
from saq.svs.validations import claim, complete, corpus_version, engine_fingerprint, fail, request_validation
from saq.svs.yara.corpus import Skipped
from saq.svs.yara.diff import Category, Outcome, ResultRow
from saq.svs.yara.replay import FileError, ReplayResult, SideReport
from tests.aceapi_v2.conftest import api_key_client, make_api_key
from tests.saq.helpers import audit_actor_of, audit_record
from tests.saq.svs.conftest import OTHER_RULE_UUID, RULE_UUID
# the repository fixtures SVS validates against
from tests.saq.svs.yara.conftest import REPOSITORY, rule_repo, stored_sample, svs_repository  # noqa: F401

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("svs_repository")]

BASE = "a" * 40
HEAD = "b" * 40
LEASE = {"lease_seconds": 300, "max_attempts": 3}
SECRET_FILE_NAME = "payroll-2026.xlsm"


def _user_id() -> int:
    return get_db().query(User.id).filter(User.username == "unittest").scalar()


def _body(**values) -> dict:
    return {"repository": REPOSITORY, "base_sha": BASE, "head_sha": HEAD, "branch": "feature",
            "pr_url": "https://git.example/pr/7", **values}


def _row(category: Category, sha256: str, rule_uuid: str = RULE_UUID, rule_name: str = "svs_rule") -> ResultRow:
    return ResultRow(sha256=sha256, rule_uuid=rule_uuid, rule_name=rule_name, namespace="acme", label="tp",
                     label_source="inherited_single", base=Outcome.MATCH, head=Outcome.MISS, raw_base=True,
                     raw_head=False, category=category)


def _completed(rows: list[ResultRow], *, head: str = HEAD) -> str:
    """A completed validation of BASE..head whose report lists rows."""
    validation_uuid, _ = request_validation(REPOSITORY, BASE, head, "feature", None, _user_id())
    claimed = claim("node1", **LEASE)
    counts = {category.value: 0 for category in Category}
    for row in rows:
        counts[row.category.value] += 1
    result = ReplayResult(
        repository=REPOSITORY, base_sha=BASE, head_sha=head, base=SideReport(sha=BASE),
        head=SideReport(sha=head, file_errors=[FileError("yara/acme/broken.yar", "acme", "syntax error")]),
        diffed=True, rows=rows, counts=counts,
        skipped=[Skipped("ef" * 32, f"files/{SECRET_FILE_NAME}", "unsafe_path")])
    complete(claimed, result, corpus_version_=corpus_version(), engine_fingerprint_=engine_fingerprint(REPOSITORY))
    return validation_uuid


#
# CI
#

class TestRequest:
    @pytest.mark.asyncio
    async def test_a_request_is_queued_then_shared(self, client: AsyncClient, client_actor,
                                                   caplog: pytest.LogCaptureFixture):
        caplog.set_level(logging.INFO)
        response = await client.post("/svs/yara/validations/", json=_body(base_sha=BASE.upper()))
        assert response.status_code == 202, response.text
        status = response.json()
        assert (status["state"], status["base_sha"], status["branch"]) == ("queued", BASE, "feature")
        assert status["report_path"] == f"/ace/signatures/validations/{status['uuid']}"

        again = await client.post("/svs/yara/validations/", json=_body())
        assert again.status_code == 200
        assert again.json()["uuid"] == status["uuid"]
        records = [r for r in caplog.records
                   if r.getMessage().startswith(f"AUDIT: unittest requested svs validation {status['uuid']}")]
        assert [r.getMessage().rsplit(": ", 1)[1] for r in records] == [
            "queued", "answered by an existing queued validation"]
        assert [(*audit_actor_of(r), r.validation_uuid, r.repository) for r in records] == [
            (*client_actor, status["uuid"], REPOSITORY)] * 2

    @pytest.mark.asyncio
    async def test_bad_requests(self, client: AsyncClient):
        response = await client.post("/svs/yara/validations/", json=_body(repository="elsewhere"))
        assert response.status_code == 422
        assert "svs.yara.repositories" in response.json()["detail"]
        # abbreviated commits would not be recognized as the same commit
        assert (await client.post("/svs/yara/validations/", json=_body(head_sha="b" * 12))).status_code == 422
        assert (await client.post("/svs/yara/validations/", json=_body(pr_url="javascript:alert(1)"))).status_code == 422

    def test_a_key_without_a_user_cannot_request(self):
        with pytest.raises(HTTPException) as error:
            service.request(ValidationRequest(**_body()), None)
        assert error.value.status_code == 422

    @pytest.mark.asyncio
    async def test_the_status_names_rules_and_never_a_sample(self, client: AsyncClient):
        sha256s = ["11" * 32, "22" * 32, "33" * 32]
        validation_uuid = _completed([
            _row(Category.REGRESSION, sha256s[0]),
            _row(Category.REGRESSION, sha256s[1]),
            _row(Category.NEW_FP_OTHER_RULE, sha256s[2], OTHER_RULE_UUID, "other_rule"),
        ])

        response = await client.get(f"/svs/yara/validations/{validation_uuid}/status")

        assert response.status_code == 200, response.text
        status = response.json()
        assert status["state"] == "completed"
        assert status["counts"]["regression"] == 2
        assert status["rules"] == {
            "regression": [{"rule_uuid": RULE_UUID, "rule_name": "svs_rule", "count": 2}],
            "new_fp_other_rule": [{"rule_uuid": OTHER_RULE_UUID, "rule_name": "other_rule", "count": 1}],
        }
        assert status["compile_errors"] == [{"file": "yara/acme/broken.yar", "error": "syntax error"}]
        for secret in (*sha256s, "ef" * 32, SECRET_FILE_NAME):
            assert secret not in response.text

    @pytest.mark.asyncio
    async def test_unknown_and_malformed_validations(self, client: AsyncClient):
        assert (await client.get(f"/svs/yara/validations/{uuid.uuid4()}/status")).status_code == 404
        assert (await client.get("/svs/yara/validations/nope/status")).status_code == 400
        assert (await client.get(f"/svs/yara/validations/{uuid.uuid4()}")).status_code == 404


class TestAccess:
    @pytest.mark.asyncio
    async def test_the_ci_key_requests_and_reads_status_only(self, _override_db_session, session: AsyncSession,
                                                              test_user):
        validation_uuid = _completed([_row(Category.REGRESSION, "11" * 32)])
        key = await make_api_key(session, test_user.id, inherit=False, scope=[("svs", "validate")])
        async with api_key_client(key) as client:
            assert (await client.post("/svs/yara/validations/", json=_body(head_sha="c" * 40))).status_code == 202
            assert (await client.get(f"/svs/yara/validations/{validation_uuid}/status")).status_code == 200
            for path in ("/svs/yara/validations/", f"/svs/yara/validations/{validation_uuid}",
                         f"/svs/yara/validations/{validation_uuid}/results",
                         f"/svs/yara/validations/{validation_uuid}/download", "/svs/samples/"):
                assert (await client.get(path)).status_code == 403, path

    @pytest.mark.asyncio
    async def test_a_reader_cannot_request(self, _override_db_session, session: AsyncSession, test_user):
        validation_uuid = _completed([])
        key = await make_api_key(session, test_user.id, inherit=False, scope=[("signature", "read")])
        async with api_key_client(key) as client:
            assert (await client.post("/svs/yara/validations/", json=_body(head_sha="c" * 40))).status_code == 403
            assert (await client.get(f"/svs/yara/validations/{validation_uuid}/status")).status_code == 403
            assert (await client.get("/svs/yara/validations/")).status_code == 200
            assert (await client.get(f"/svs/yara/validations/{validation_uuid}/download")).status_code == 403

    @pytest.mark.asyncio
    async def test_no_permission(self, noperm_client: AsyncClient):
        assert (await noperm_client.post("/svs/yara/validations/", json=_body())).status_code == 403
        assert (await noperm_client.get("/svs/yara/validations/")).status_code == 403


#
# readers
#

class TestListing:
    @pytest.mark.asyncio
    async def test_filters_pages_and_exports(self, client: AsyncClient):
        regressed = _completed([_row(Category.REGRESSION, "11" * 32)])
        clean = _completed([], head="c" * 40)
        request_validation(REPOSITORY, BASE, "d" * 40, "feature", None, _user_id())
        fail(claim("node1", **LEASE), "the scan failed")

        async def _uuids(*filters, **params):
            response = await client.get("/svs/yara/validations/", params={"f": list(filters), **params})
            assert response.status_code == 200, response.text
            return [row["uuid"] for row in response.json()["data"]]

        assert await _uuids("has_regressions:true") == [regressed]
        # the inverse keeps the failed validation, which has no counts
        assert len(await _uuids("!has_regressions:true")) == 2
        assert set(await _uuids("state:completed")) == {regressed, clean}
        assert await _uuids("head:cccc") == [clean]
        assert len(await _uuids("state:failed")) == 1
        assert (await client.get("/svs/yara/validations/", params={"f": "state:done"})).status_code == 422

        # keyset pages, newest first
        first = await client.get("/svs/yara/validations/", params={"limit": 2})
        second = await client.get("/svs/yara/validations/", params={"limit": 2, "cursor": first.json()["next_cursor"]})
        listed = [row["uuid"] for row in first.json()["data"] + second.json()["data"]]
        assert len(set(listed)) == 3 and second.json()["next_cursor"] is None
        assert listed == await _uuids()
        assert (await client.get("/svs/yara/validations/", params={"cursor": "junk"})).status_code == 400

        row = next(row for row in first.json()["data"] + second.json()["data"] if row["uuid"] == regressed)
        assert (row["regressions"], row["new_fps"], row["compile_errors"], row["requested_by"]) == (1, 0, 1, "unittest")

        ndjson = await client.get("/svs/yara/validations/export/ndjson", params={"f": "has_regressions:true"})
        assert [json.loads(line)["uuid"] for line in ndjson.text.splitlines()] == [regressed]
        exported = list(csv.DictReader(io.StringIO((await client.get("/svs/yara/validations/export/csv")).text)))
        assert {line["uuid"] for line in exported} == set(listed)
        assert "counts" not in exported[0]

    @pytest.mark.asyncio
    async def test_the_detail_carries_the_report(self, client: AsyncClient):
        validation_uuid = _completed([_row(Category.REGRESSION, "11" * 32)])
        detail = (await client.get(f"/svs/yara/validations/{validation_uuid}")).json()
        assert (detail["state"], detail["attempts"], detail["claimed_by"]) == ("completed", 1, "node1")
        assert detail["report"]["skipped"][0]["file_path"] == f"files/{SECRET_FILE_NAME}"
        assert detail["report"]["head"]["file_errors"][0]["file"] == "yara/acme/broken.yar"


class TestResults:
    @pytest.mark.asyncio
    async def test_rows_by_category_and_rule(self, client: AsyncClient):
        validation_uuid = _completed([
            _row(Category.REGRESSION, "11" * 32),
            _row(Category.REGRESSION, "22" * 32),
            _row(Category.NEW_FP, "33" * 32, OTHER_RULE_UUID),
        ])
        path = f"/svs/yara/validations/{validation_uuid}/results"

        rows = (await client.get(path)).json()["data"]
        assert [row["sha256"] for row in rows] == ["11" * 32, "22" * 32, "33" * 32]
        assert rows[0]["label"] == "tp" and rows[0]["base"] == "match"

        assert len((await client.get(path, params={"category": "regression"})).json()["data"]) == 2
        assert [row["sha256"] for row in (await client.get(path, params={"rule_uuid": OTHER_RULE_UUID})).json()["data"]] == ["33" * 32]
        first = await client.get(path, params={"limit": 2})
        second = await client.get(path, params={"limit": 2, "cursor": first.json()["next_cursor"]})
        assert [row["sha256"] for row in second.json()["data"]] == ["33" * 32]

        assert (await client.get(path, params={"category": "known_fp"})).status_code == 422
        exported = list(csv.DictReader(io.StringIO((await client.get(f"{path}/export/csv")).text)))
        assert [line["category"] for line in exported] == ["regression", "regression", "new_fp"]
        ndjson = (await client.get(f"{path}/export/ndjson", params={"category": "new_fp"})).text.splitlines()
        assert [json.loads(line)["sha256"] for line in ndjson] == ["33" * 32]

    @pytest.mark.asyncio
    async def test_the_selection_downloads_as_an_encrypted_zip(self, client: AsyncClient, client_actor,
                                                               caplog: pytest.LogCaptureFixture):
        caplog.set_level(logging.INFO)
        stored = stored_sample("DELIVERY", b"svs validation download", [RULE_UUID])
        validation_uuid = _completed([
            _row(Category.REGRESSION, stored),
            # another rule's pair: the file still downloads, with its own samples' records
            _row(Category.NEW_FP_OTHER_RULE, stored, OTHER_RULE_UUID),
            _row(Category.NEW_FP, "99" * 32),
        ])

        response = await client.get(f"/svs/yara/validations/{validation_uuid}/download",
                                    params={"category": ["regression", "new_fp_other_rule"]})

        assert response.status_code == 200, response.text
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            names = archive.namelist()
            assert any(name.endswith(f"/{stored}/sample.bin") for name in names)
            manifest = json.loads(archive.read(f"svs-validation-{validation_uuid}/manifest.json", pwd=b"infected"))
        assert [entry["sha256"] for entry in manifest["files"]] == [stored]
        audit = audit_record(caplog, f"user unittest downloading 1 svs sample files of validation {validation_uuid}")
        assert (*audit_actor_of(audit), audit.validation_uuid, audit.sha256s) == (
            *client_actor, validation_uuid, [stored])

        # nothing of the selection is stored
        nothing = await client.get(f"/svs/yara/validations/{validation_uuid}/download", params={"category": "new_fp"})
        assert nothing.status_code == 404
