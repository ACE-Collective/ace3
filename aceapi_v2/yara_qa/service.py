"""YARA QA results: the rules in QA mode, what they matched, and the files (docs/YARA_QA.md).

The listing merges the rule inventory (rules in QA mode, including ones that never matched) with
the counters in yara_qa_signatures (saq/yara_qa/listing.py). Files and match records are objects in
the yara_qa CAS pool. With a node-local pool the bytes are only on the node that stored them, so
anything that reads bytes answers 409 wrong_node for a match stored elsewhere; a site that
redefines the pool with a shared backend (shared: true) never sees that.
"""

import json
import logging
import os
import tempfile
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from aceapi_v2.common.archive import MANIFEST_NAME, CASArchiveEntry, create_encrypted_cas_zip, safe_file_name
from aceapi_v2.yara_qa.schemas import (
    QAMatch,
    QAMatchDetail,
    QAPage,
    QASignatureDetail,
    QASignaturePage,
    QASignatureSummary,
    QASignatureVersion,
)
from saq.cas import get_cas
from saq.cas.errors import ObjectNotFound
from saq.configuration.config import get_config
from saq.database.model import Alert, YaraQAMatch
from saq.environment import get_global_runtime_settings, get_temp_dir
from saq.signatures.model import SIGNATURE_UUID_PATTERN, YaraInventory
from saq.yara_qa.listing import QASignature, QASort, QAStatus, filter_and_sort, merge, version_rows_statement

logger = logging.getLogger(__name__)

_MATCH_RECORD_NAME = "match.json"
_RESERVED_ENTRY_NAMES = {_MATCH_RECORD_NAME, MANIFEST_NAME}


def _load_inventory() -> YaraInventory:
    # local import: the signature loaders import the hunter, and through it the engine, which
    # imports aceapi_v2 back (a circular import at startup)
    from saq.signatures.yara_inventory import get_yara_inventory

    return get_yara_inventory(get_config().yara_qa.inventory_refresh_seconds)


def validate_signature_uuid(signature_uuid: str) -> None:
    if not SIGNATURE_UUID_PATTERN.match(signature_uuid):
        raise HTTPException(status_code=400, detail="invalid signature uuid")


def _local_node() -> Optional[str]:
    return get_global_runtime_settings().saq_node


def pool_is_shared() -> bool:
    pool_config = get_config().cas.pools.get(get_config().yara_qa.pool)
    return pool_config is not None and pool_config.shared


def is_local(row: YaraQAMatch) -> bool:
    """Whether this node can read the match's bytes: always with a shared pool, otherwise only on
    the node that stored them."""
    return pool_is_shared() or row.node == _local_node()


def _raise_wrong_node(row: YaraQAMatch) -> None:
    """409 rather than 404, naming the node: "it is on another node" tells the analyst where to
    go; "not found" would not. Same shape as the crash report download."""
    raise HTTPException(
        status_code=409,
        detail={
            "error": "wrong_node",
            "node": row.node,
            "message": (
                f"yara qa match {row.id} is stored on node {row.node} and is not reachable from here; "
                "request it from that node's API, or give the yara_qa pool a shared backend"
            ),
        },
    )


#
# signatures
#

def _signature_summary(signature: QASignature) -> QASignatureSummary:
    return QASignatureSummary(
        signature_uuid=signature.signature_uuid, name=signature.name, status=signature.status.value,
        enabled=signature.enabled, current_version=signature.current_version,
        source_path=signature.source_path, tags=list(signature.tags), namespace=signature.namespace,
        match_count=signature.match_count, stored_count=signature.stored_count,
        version_count=signature.version_count, first_match_at=signature.first_match_at,
        last_match_at=signature.last_match_at)


async def list_signatures(session: AsyncSession, *, q: Optional[str], status: Optional[QAStatus],
                          has_matches: Optional[bool], sort: QASort, descending: bool,
                          limit: int, offset: int) -> QASignaturePage:
    inventory = await run_in_threadpool(_load_inventory)
    rows = (await session.execute(version_rows_statement())).scalars().all()
    signatures = filter_and_sort(merge(inventory, rows), q=q, status=status, has_matches=has_matches,
                                 sort=sort, descending=descending)
    return QASignaturePage(
        data=[_signature_summary(s) for s in signatures[offset:offset + limit]],
        total=len(signatures), limit=limit, offset=offset, inventory_error=inventory.error)


async def get_signature(session: AsyncSession, signature_uuid: str) -> QASignatureDetail:
    validate_signature_uuid(signature_uuid)
    inventory = await run_in_threadpool(_load_inventory)
    rows = (await session.execute(version_rows_statement(signature_uuid))).scalars().all()
    signature = next((s for s in merge(inventory, rows) if s.signature_uuid == signature_uuid), None)
    if signature is None:
        raise HTTPException(status_code=404, detail="no rule in qa mode and no qa matches for this signature uuid")

    return QASignatureDetail(
        **_signature_summary(signature).model_dump(),
        versions=[QASignatureVersion(
            signature_version=v.signature_version, rule_name=v.rule_name, namespace=v.namespace,
            match_count=v.match_count, stored_count=v.stored_count,
            first_match_at=v.first_match_at, last_match_at=v.last_match_at) for v in signature.versions])


#
# matches
#

def _stored():
    # a NULL match_digest is a match whose puts are still in flight (or were interrupted)
    return YaraQAMatch.match_digest.is_not(None)


async def _alert_uuids(session: AsyncSession, root_uuids: set[str]) -> set[str]:
    if not root_uuids:
        return set()

    return set((await session.execute(select(Alert.uuid).where(Alert.uuid.in_(root_uuids)))).scalars().all())


def _match(row: YaraQAMatch, alert_uuids: set[str]) -> dict:
    return dict(
        id=row.id, signature_uuid=row.signature_uuid, signature_version=row.signature_version,
        sha256=row.sha256, file_name=row.file_name, file_size=row.file_size, hit_count=row.hit_count,
        first_seen=row.first_seen, last_seen=row.last_seen, expires_at=row.expires_at, node=row.node,
        local=is_local(row), root_uuid=row.root_uuid, observable_uuid=row.observable_uuid,
        alert_uuid=row.root_uuid if row.root_uuid in alert_uuids else None)


async def list_matches(session: AsyncSession, signature_uuid: str, *, version: Optional[str],
                       limit: int, offset: int) -> QAPage[QAMatch]:
    validate_signature_uuid(signature_uuid)
    conditions = [YaraQAMatch.signature_uuid == signature_uuid, _stored()]
    if version is not None:
        conditions.append(YaraQAMatch.signature_version == version)

    total = (await session.execute(select(func.count()).select_from(YaraQAMatch).where(*conditions))).scalar_one()
    rows = (await session.execute(
        select(YaraQAMatch).where(*conditions).order_by(YaraQAMatch.id.desc()).limit(limit).offset(offset)
    )).scalars().all()

    alert_uuids = await _alert_uuids(session, {row.root_uuid for row in rows})
    return QAPage[QAMatch](data=[QAMatch(**_match(row, alert_uuids)) for row in rows],
                           total=total, limit=limit, offset=offset)


async def _get_match_row(session: AsyncSession, match_id: int) -> YaraQAMatch:
    row = (await session.execute(select(YaraQAMatch).where(YaraQAMatch.id == match_id, _stored()))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="yara qa match not found")

    return row


async def get_match(session: AsyncSession, match_id: int) -> QAMatchDetail:
    row = await _get_match_row(session, match_id)
    alert_uuids = await _alert_uuids(session, {row.root_uuid})
    try:
        match_summary = json.loads(row.match_summary) if row.match_summary else {}
    except ValueError:
        logger.warning("yara qa match %s has an unreadable match summary", row.id)
        match_summary = {}

    return QAMatchDetail(**_match(row, alert_uuids), match_summary=match_summary)


async def resolve_record(session: AsyncSession, match_id: int) -> YaraQAMatch:
    row = await _get_match_row(session, match_id)
    if not is_local(row):
        _raise_wrong_node(row)

    return row


def materialize_record(row: YaraQAMatch) -> str:
    """The match record in a private temp file; the caller removes it."""
    fd, path = tempfile.mkstemp(prefix=f"yara-qa-record-{row.id}-", suffix=".json", dir=get_temp_dir())
    os.close(fd)
    os.remove(path)  # materialize() requires that the destination does not exist
    try:
        get_cas().pool(get_config().yara_qa.pool).materialize(row.match_digest, path)
    except ObjectNotFound:
        raise HTTPException(status_code=404, detail="the match record is no longer stored") from None

    return path


#
# downloads
#

async def resolve_single_download(session: AsyncSession, match_id: int) -> YaraQAMatch:
    row = await _get_match_row(session, match_id)
    if not is_local(row):
        _raise_wrong_node(row)

    return row


async def resolve_bulk_download(session: AsyncSession, signature_uuid: str, *, version: Optional[str],
                                match_ids: list[int]) -> tuple[list[YaraQAMatch], list[YaraQAMatch]]:
    """(the matches this node can serve, the ones stored on other nodes) for one bulk download,
    after enforcing the bulk limits on the first."""
    validate_signature_uuid(signature_uuid)
    config = get_config().yara_qa
    conditions = [YaraQAMatch.signature_uuid == signature_uuid, _stored()]
    if version is not None:
        conditions.append(YaraQAMatch.signature_version == version)
    if match_ids:
        conditions.append(YaraQAMatch.id.in_(match_ids))

    # one more than the limit is enough to know it was exceeded
    rows = (await session.execute(
        select(YaraQAMatch).where(*conditions).order_by(YaraQAMatch.id)
        .limit(config.max_bulk_download_files + 1))).scalars().all()

    if match_ids:
        missing = set(match_ids) - {row.id for row in rows}
        if missing:
            raise HTTPException(status_code=404, detail=f"no stored matches of this signature with ids {sorted(missing)}")

    local = [row for row in rows if is_local(row)]
    remote = [row for row in rows if not is_local(row)]

    if not rows:
        raise HTTPException(status_code=404, detail="no stored matches to download")

    if not local:
        _raise_wrong_node(remote[0])

    if len(rows) > config.max_bulk_download_files:
        raise HTTPException(status_code=413, detail=(
            f"more than {config.max_bulk_download_files} files; narrow the download by version or match_id"))

    total_bytes = sum(row.file_size for row in local)
    if total_bytes > config.max_bulk_download_bytes:
        raise HTTPException(status_code=413, detail=(
            f"{total_bytes} bytes is more than {config.max_bulk_download_bytes}; narrow the download by version or match_id"))

    return local, remote


def _manifest_entry(row: YaraQAMatch) -> dict:
    return {
        "match_id": row.id, "signature_uuid": row.signature_uuid, "signature_version": row.signature_version,
        "sha256": row.sha256, "file_name": row.file_name, "file_size": row.file_size,
        "hit_count": row.hit_count, "first_seen": row.first_seen.isoformat(), "last_seen": row.last_seen.isoformat(),
        "root_uuid": row.root_uuid, "observable_uuid": row.observable_uuid, "node": row.node,
    }


def create_encrypted_zip(label: str, rows: list[YaraQAMatch], remote: list[YaraQAMatch],
                         actor: Optional[str]) -> tuple[str, str]:
    """Zip the files and match records of rows, encrypted with the password infected
    (aceapi_v2/common/archive.py). Returns (zip path, staging directory); the caller removes the
    staging directory, which holds the zip.

    Layout, under one top-level directory named after label:
        manifest.json                       what is in the zip, and what was skipped and why
        <match id>-<sha256>/<file name>     the file, under a sanitized version of its name
        <match id>-<sha256>/match.json      the full match record"""
    entries = []
    for row in rows:
        entry_dir = f"{row.id}-{row.sha256}"
        file_name = safe_file_name(row.file_name, reserved=_RESERVED_ENTRY_NAMES)
        entries.append(CASArchiveEntry(
            directory=entry_dir,
            members=((file_name, row.sha256), (_MATCH_RECORD_NAME, row.match_digest)),
            manifest=_manifest_entry(row),
            included={**_manifest_entry(row), "path": f"{entry_dir}/{file_name}",
                      "match_record": f"{entry_dir}/{_MATCH_RECORD_NAME}"}))

    return create_encrypted_cas_zip(
        label, get_cas().pool(get_config().yara_qa.pool), entries,
        [{**_manifest_entry(row), "reason": "wrong_node"} for row in remote],
        manifest_key="matches", description=f"yara qa {label}", actor=actor, node=_local_node())
