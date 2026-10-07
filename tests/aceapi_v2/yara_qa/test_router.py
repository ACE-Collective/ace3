"""Tests for the YARA QA results endpoints (docs/YARA_QA.md).

Integration tests: authentication is database backed. Rows are written through the shared test
session (rolled back after each test); the CAS objects they point at are real puts into the
yara_qa pool.
"""

import io
import json
import zipfile
from datetime import datetime, timedelta
from typing import Optional

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from saq.cas import get_cas
from saq.configuration.config import get_config, get_service_config
from saq.constants import SERVICE_YARA_SCANNER
from saq.database.model import YaraQAMatch, YaraQASignature
from saq.environment import get_global_runtime_settings
from saq.yara_scanning.match_record import serialize_match_record, summarize_match_record
from tests.aceapi_v2.conftest import api_key_client, make_api_key

pytestmark = pytest.mark.integration

MATCHED_UUID = "5a0c7f1e-1c43-4a39-8d8e-2f1b3c4d5e6f"
NEVER_MATCHED_UUID = "6b1d8a2f-2d54-4b4a-9e9f-3a2c4d5e6f70"
OTHER_UUID = "7c2e9b3a-3e65-4c5b-8fa0-4b3d5e6f7081"
VERSION_A = "a" * 40
VERSION_B = "b" * 40

RULES = f"""\
rule matched_qa_rule
{{
    meta:
        uuid = "{MATCHED_UUID}"
        modifiers = "qa"
    strings:
        $a = "matched"
    condition:
        $a
}}

rule never_matched_qa_rule
{{
    meta:
        uuid = "{NEVER_MATCHED_UUID}"
        modifiers = "qa"
    strings:
        $a = "never"
    condition:
        $a
}}

rule not_qa_rule
{{
    meta:
        uuid = "{OTHER_UUID}"
    strings:
        $a = "plain"
    condition:
        $a
}}
"""


@pytest.fixture(autouse=True)
def signature_dir(tmp_path, monkeypatch) -> str:
    root = tmp_path / "yara"
    (root / "unittest").mkdir(parents=True)
    (root / "unittest" / "rules.yar").write_text(RULES)
    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "signature_dir", str(root))
    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "git_repo_dirs", [])
    return str(root)


def _match_result(signature_uuid: str, version: str) -> dict:
    return {
        "target": "/tmp/scan.target", "rule": "matched_qa_rule", "namespace": "unittest",
        "commit": version, "tags": ["unittest"], "meta": {"uuid": signature_uuid, "modifiers": "qa"},
        "strings": [(0, "$a", b"matched"), (40, "$a", b"matched")],
    }


async def _counters(session: AsyncSession, signature_uuid: str, version: str, match_count: int,
                    stored_count: int, last_match_at: datetime) -> None:
    session.add(YaraQASignature(
        signature_uuid=signature_uuid, signature_version=version, rule_name="matched_qa_rule",
        namespace="unittest", match_count=match_count, stored_count=stored_count,
        first_match_at=last_match_at - timedelta(days=1), last_match_at=last_match_at))
    await session.flush()


async def _stored_match(session: AsyncSession, content: bytes, *, signature_uuid: str = MATCHED_UUID,
                        version: str = VERSION_A, file_name: str = "invoice.doc",
                        node: Optional[str] = None, stored: bool = True) -> YaraQAMatch:
    pool = get_cas().pool("yara_qa")
    match_result = _match_result(signature_uuid, version)
    sha256 = pool.put(content)
    match_digest = pool.put(serialize_match_record(match_result)) if stored else None
    now = datetime.now()
    row = YaraQAMatch(
        signature_uuid=signature_uuid, signature_version=version, sha256=sha256, file_name=file_name,
        file_size=len(content), root_uuid="11111111-2222-3333-4444-555555555555",
        observable_uuid="66666666-7777-8888-9999-000000000000",
        node=node or get_global_runtime_settings().saq_node, match_digest=match_digest,
        match_summary=json.dumps(summarize_match_record(match_result)), hit_count=1,
        first_seen=now, last_seen=now, expires_at=now + timedelta(days=30))
    session.add(row)
    await session.flush()
    return row


def _open_zip(content: bytes) -> tuple[zipfile.ZipFile, dict]:
    archive = zipfile.ZipFile(io.BytesIO(content))
    archive.setpassword(b"infected")
    manifest_name = next(name for name in archive.namelist() if name.endswith("/manifest.json"))
    return archive, json.loads(archive.read(manifest_name))


#
# authentication and permissions
#

@pytest.mark.asyncio
async def test_requires_authentication(unauth_client: AsyncClient):
    assert (await unauth_client.get("/signatures/yara-qa/")).status_code == 401
    assert (await unauth_client.get("/signatures/yara-qa/matches/1/download")).status_code == 401


@pytest.mark.asyncio
async def test_requires_permission(noperm_client: AsyncClient):
    assert (await noperm_client.get("/signatures/yara-qa/")).status_code == 403
    assert (await noperm_client.get(f"/signatures/yara-qa/{MATCHED_UUID}/matches")).status_code == 403
    assert (await noperm_client.get("/signatures/yara-qa/matches/1/download")).status_code == 403


@pytest.mark.asyncio
async def test_read_permission_does_not_download(_override_db_session, session: AsyncSession, test_user):
    row = await _stored_match(session, b"sample bytes")
    key = await make_api_key(session, test_user.id, inherit=False, scope=[("signature", "read")])
    async with api_key_client(key) as client:
        assert (await client.get("/signatures/yara-qa/")).status_code == 200
        assert (await client.get(f"/signatures/yara-qa/matches/{row.id}")).status_code == 200
        assert (await client.get(f"/signatures/yara-qa/matches/{row.id}/record")).status_code == 200
        assert (await client.get(f"/signatures/yara-qa/matches/{row.id}/download")).status_code == 403
        assert (await client.get(f"/signatures/yara-qa/{MATCHED_UUID}/download")).status_code == 403


#
# signatures
#

@pytest.mark.asyncio
async def test_list_includes_rules_that_never_matched(client: AsyncClient, session: AsyncSession):
    await _counters(session, MATCHED_UUID, VERSION_A, 10, 2, datetime(2026, 9, 1))
    await _counters(session, MATCHED_UUID, VERSION_B, 4, 1, datetime(2026, 9, 20))

    response = await client.get("/signatures/yara-qa/")
    assert response.status_code == 200
    page = response.json()
    assert page["total"] == 2
    assert page["inventory_error"] is None

    by_uuid = {s["signature_uuid"]: s for s in page["data"]}
    assert set(by_uuid) == {MATCHED_UUID, NEVER_MATCHED_UUID}

    matched = by_uuid[MATCHED_UUID]
    assert (matched["name"], matched["status"], matched["enabled"]) == ("matched_qa_rule", "qa", True)
    assert (matched["match_count"], matched["stored_count"], matched["version_count"]) == (14, 3, 2)
    assert matched["last_match_at"].startswith("2026-09-20")

    never = by_uuid[NEVER_MATCHED_UUID]
    assert (never["match_count"], never["stored_count"], never["version_count"]) == (0, 0, 0)
    assert never["last_match_at"] is None


@pytest.mark.asyncio
async def test_list_filters_and_pages(client: AsyncClient, session: AsyncSession):
    await _counters(session, MATCHED_UUID, VERSION_A, 3, 1, datetime(2026, 9, 1))
    # a rule that left qa mode but has recorded matches
    await _counters(session, OTHER_UUID, VERSION_A, 1, 1, datetime(2026, 8, 1))

    async def names(**params):
        response = await client.get("/signatures/yara-qa/", params=params)
        assert response.status_code == 200
        return [s["name"] for s in response.json()["data"]]

    assert await names() == ["matched_qa_rule", "never_matched_qa_rule", "not_qa_rule"]
    assert await names(status="qa") == ["matched_qa_rule", "never_matched_qa_rule"]
    assert await names(status="not_qa") == ["not_qa_rule"]
    assert await names(has_matches="false") == ["never_matched_qa_rule"]
    assert await names(q="NEVER") == ["never_matched_qa_rule"]
    assert await names(q=OTHER_UUID[:8]) == ["not_qa_rule"]
    assert await names(sort="match_count", descending="true") == ["matched_qa_rule", "not_qa_rule", "never_matched_qa_rule"]

    response = await client.get("/signatures/yara-qa/", params={"limit": 1, "offset": 1})
    page = response.json()
    assert (page["total"], page["limit"], page["offset"]) == (3, 1, 1)
    assert [s["name"] for s in page["data"]] == ["never_matched_qa_rule"]


@pytest.mark.asyncio
@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 501}, {"offset": -1}, {"status": "bogus"}])
async def test_list_rejects_bad_parameters(client: AsyncClient, params):
    assert (await client.get("/signatures/yara-qa/", params=params)).status_code == 422


@pytest.mark.asyncio
async def test_get_signature(client: AsyncClient, session: AsyncSession):
    await _counters(session, MATCHED_UUID, VERSION_A, 10, 2, datetime(2026, 9, 1))
    await _counters(session, MATCHED_UUID, VERSION_B, 4, 1, datetime(2026, 9, 20))

    response = await client.get(f"/signatures/yara-qa/{MATCHED_UUID}")
    assert response.status_code == 200
    detail = response.json()
    assert [v["signature_version"] for v in detail["versions"]] == [VERSION_B, VERSION_A]
    assert [v["match_count"] for v in detail["versions"]] == [4, 10]

    never = (await client.get(f"/signatures/yara-qa/{NEVER_MATCHED_UUID}")).json()
    assert never["versions"] == []

    # a rule that is not in qa mode and never matched in it is not a qa signature
    assert (await client.get(f"/signatures/yara-qa/{OTHER_UUID}")).status_code == 404
    assert (await client.get("/signatures/yara-qa/not;a;uuid")).status_code == 400


#
# matches
#

@pytest.mark.asyncio
async def test_list_matches(client: AsyncClient, session: AsyncSession):
    first = await _stored_match(session, b"first sample", version=VERSION_A)
    second = await _stored_match(session, b"second sample", version=VERSION_B, node="some-other-node")
    # puts still in flight: not listed
    await _stored_match(session, b"in flight", stored=False)

    response = await client.get(f"/signatures/yara-qa/{MATCHED_UUID}/matches")
    assert response.status_code == 200
    page = response.json()
    assert page["total"] == 2
    assert [m["id"] for m in page["data"]] == [second.id, first.id]
    assert [m["local"] for m in page["data"]] == [False, True]
    assert page["data"][1]["sha256"] == first.sha256
    assert page["data"][1]["alert_uuid"] is None

    response = await client.get(f"/signatures/yara-qa/{MATCHED_UUID}/matches", params={"version": VERSION_A})
    assert [m["id"] for m in response.json()["data"]] == [first.id]


@pytest.mark.asyncio
async def test_get_match_and_full_record(client: AsyncClient, session: AsyncSession):
    row = await _stored_match(session, b"a sample")

    detail = (await client.get(f"/signatures/yara-qa/matches/{row.id}")).json()
    assert detail["match_summary"]["strings"] == [{"identifier": "$a", "count": 2, "first_offset": 0}]

    response = await client.get(f"/signatures/yara-qa/matches/{row.id}/record")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["content-disposition"].startswith("inline")
    assert response.content == serialize_match_record(_match_result(MATCHED_UUID, VERSION_A))

    assert (await client.get("/signatures/yara-qa/matches/999999")).status_code == 404


#
# downloads
#

@pytest.mark.asyncio
async def test_download_one_match(client: AsyncClient, session: AsyncSession):
    row = await _stored_match(session, b"MZ live malware stand-in", file_name="../../evil.doc")

    response = await client.get(f"/signatures/yara-qa/matches/{row.id}/download")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert f"yara-qa-match-{row.id}.zip" in response.headers["content-disposition"]

    archive, manifest = _open_zip(response.content)
    top = f"yara-qa-match-{row.id}"
    assert archive.read(f"{top}/{row.id}-{row.sha256}/evil.doc") == b"MZ live malware stand-in"
    assert json.loads(archive.read(f"{top}/{row.id}-{row.sha256}/match.json"))["rule"] == "matched_qa_rule"
    assert [m["match_id"] for m in manifest["matches"]] == [row.id]
    assert manifest["skipped"] == []

    # encrypted: unreadable without the password
    locked = zipfile.ZipFile(io.BytesIO(response.content))
    with pytest.raises(RuntimeError):
        locked.read(f"{top}/{row.id}-{row.sha256}/evil.doc")


@pytest.mark.asyncio
async def test_bulk_download(client: AsyncClient, session: AsyncSession):
    first = await _stored_match(session, b"first sample", version=VERSION_A)
    second = await _stored_match(session, b"second sample", version=VERSION_B)
    remote = await _stored_match(session, b"remote sample", version=VERSION_B, node="some-other-node")

    response = await client.get(f"/signatures/yara-qa/{MATCHED_UUID}/download")
    assert response.status_code == 200
    archive, manifest = _open_zip(response.content)
    assert sorted(m["match_id"] for m in manifest["matches"]) == [first.id, second.id]
    assert [(s["match_id"], s["reason"]) for s in manifest["skipped"]] == [(remote.id, "wrong_node")]
    assert archive.read(f"yara-qa-{MATCHED_UUID}/{second.id}-{second.sha256}/invoice.doc") == b"second sample"

    # one version
    response = await client.get(f"/signatures/yara-qa/{MATCHED_UUID}/download", params={"version": VERSION_A})
    _, manifest = _open_zip(response.content)
    assert [m["match_id"] for m in manifest["matches"]] == [first.id]

    # a selection
    response = await client.get(f"/signatures/yara-qa/{MATCHED_UUID}/download", params={"match_id": [second.id]})
    _, manifest = _open_zip(response.content)
    assert [m["match_id"] for m in manifest["matches"]] == [second.id]


@pytest.mark.asyncio
async def test_bulk_download_selection_must_belong_to_the_signature(client: AsyncClient, session: AsyncSession):
    other = await _stored_match(session, b"other rule's sample", signature_uuid=OTHER_UUID)
    await _stored_match(session, b"this rule's sample")
    response = await client.get(f"/signatures/yara-qa/{MATCHED_UUID}/download", params={"match_id": [other.id]})
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_bulk_download_limits(client: AsyncClient, session: AsyncSession, monkeypatch):
    await _stored_match(session, b"first sample")
    await _stored_match(session, b"second sample")

    monkeypatch.setattr(get_config().yara_qa, "max_bulk_download_files", 1)
    assert (await client.get(f"/signatures/yara-qa/{MATCHED_UUID}/download")).status_code == 413

    monkeypatch.setattr(get_config().yara_qa, "max_bulk_download_files", 10)
    monkeypatch.setattr(get_config().yara_qa, "max_bulk_download_bytes", 20)
    assert (await client.get(f"/signatures/yara-qa/{MATCHED_UUID}/download")).status_code == 413

    monkeypatch.setattr(get_config().yara_qa, "max_bulk_download_bytes", 1000)
    assert (await client.get(f"/signatures/yara-qa/{MATCHED_UUID}/download")).status_code == 200


@pytest.mark.asyncio
async def test_nothing_to_download(client: AsyncClient):
    assert (await client.get(f"/signatures/yara-qa/{MATCHED_UUID}/download")).status_code == 404
    assert (await client.get("/signatures/yara-qa/matches/999999/download")).status_code == 404


@pytest.mark.asyncio
async def test_wrong_node(client: AsyncClient, session: AsyncSession):
    row = await _stored_match(session, b"stored elsewhere", node="some-other-node")

    for url in (f"/signatures/yara-qa/matches/{row.id}/download",
                f"/signatures/yara-qa/matches/{row.id}/record",
                f"/signatures/yara-qa/{MATCHED_UUID}/download"):
        response = await client.get(url)
        assert response.status_code == 409, url
        assert response.json()["detail"]["error"] == "wrong_node"
        assert response.json()["detail"]["node"] == "some-other-node"

    # the metadata is still readable
    assert (await client.get(f"/signatures/yara-qa/matches/{row.id}")).status_code == 200


@pytest.mark.asyncio
async def test_shared_pool_serves_every_node(client: AsyncClient, session: AsyncSession, monkeypatch):
    """A site that redefines the pool with a shared backend can serve a match from any node."""
    row = await _stored_match(session, b"stored elsewhere", node="some-other-node")
    monkeypatch.setattr(get_config().cas.pools["yara_qa"], "shared", True)

    page = (await client.get(f"/signatures/yara-qa/{MATCHED_UUID}/matches")).json()
    assert page["data"][0]["local"] is True
    assert (await client.get(f"/signatures/yara-qa/matches/{row.id}/download")).status_code == 200
    assert (await client.get(f"/signatures/yara-qa/matches/{row.id}/record")).status_code == 200


@pytest.mark.asyncio
async def test_expired_object_is_reported_as_gone(client: AsyncClient, session: AsyncSession):
    row = await _stored_match(session, b"collected by gc")
    get_cas().pool("yara_qa").purge(row.sha256, reason="unittest", actor="unittest")
    response = await client.get(f"/signatures/yara-qa/matches/{row.id}/download")
    assert response.status_code == 404
