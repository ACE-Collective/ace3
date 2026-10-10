"""SVS sample service for ACE API v2: the YARA samples SVS captured and their labels
(docs/SVS_SAMPLES.md, docs/SVS_API.md).

Synchronous; the router runs each function through run_db_in_thread (or run_in_threadpool for the
CAS work). The SQL is saq.svs.samples, saq.svs.filters and saq.svs.labels.

SVS data is global: nothing here is scoped to the alerts this node shows, and nothing exposes an
alert's own data beyond its uuid and the verdicts on its detections.

Files and match records are objects in the svs_samples CAS pool. With a node-local pool the bytes
are only on the node that stored them, so anything that reads bytes answers 409 wrong_node for a
sample stored elsewhere; a multi-node site gives the pool a shared backend (shared: true) and never
sees that.
"""

import base64
import csv
import io
import json
import logging
import os
import re
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import Select, select, tuple_

from aceapi_v2.common.archive import MANIFEST_NAME, CASArchiveEntry, create_encrypted_cas_zip, safe_file_name
from aceapi_v2.svs.samples.schemas import (
    SAMPLE_ROW_CSV_FIELDS,
    MissingCount,
    SampleCapture,
    SampleDetail,
    SampleDetection,
    SampleRow,
)
from saq.cas import get_cas
from saq.cas.errors import ObjectNotFound
from saq.configuration.config import get_config
from saq.database.model import SVSYaraCapture
from saq.database.pool import get_db
from saq.environment import get_global_runtime_settings, get_temp_dir
from saq.gui.filter_screens import SVS_SAMPLES_SCREEN
from saq.gui.filter_url import FilterQueryError, decode_filter_query
from saq.signatures.model import SIGNATURE_UUID_PATTERN
from saq.svs.constants import CaptureState
from saq.svs.filters import sample_filter_conditions
from saq.svs.samples import (
    SampleSort,
    bytes_nodes,
    changed_since_condition,
    contributing_detections,
    get_capture,
    get_captures,
    get_sample,
    is_local,
    keyset_condition,
    missing_by_rule,
    order_by,
    parse_json_column,
    parse_sort_key,
    sample_record,
    samples_subquery,
    sort_key,
)

logger = logging.getLogger(__name__)

LISTING_MAX_PAGE_SIZE = 1000
LISTING_EXPORT_PAGE_SIZE = 1000

_CURSOR_VERSION = 1
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class InvalidListingRequest(ValueError):
    """The filters of a listing request cannot be used; detail is a message or pydantic errors."""

    def __init__(self, detail):
        super().__init__(str(detail))
        self.detail = detail


class InvalidCursor(ValueError):
    """The cursor is malformed, or belongs to a listing in another order."""


#
# where the bytes are
#

def _local_node() -> Optional[str]:
    return get_global_runtime_settings().saq_node


def _pool_name() -> str:
    return get_config().svs.samples.pool


def _raise_wrong_node(node: str, what: str) -> None:
    """409 rather than 404, naming the node: "it is on another node" tells the analyst where to
    go; "not found" would not. Same shape as the YARA QA and crash report downloads."""
    raise HTTPException(
        status_code=409,
        detail={
            "error": "wrong_node",
            "node": node,
            "message": (
                f"{what} is stored on node {node} and is not reachable from here; request it from that "
                f"node's API, or give the {_pool_name()} pool a shared backend"
            ),
        },
    )


#
# validation
#

def validate_sample_key(sha256: str, rule_uuid: str) -> str:
    """The sha256, lowercased. 400 on a malformed sha256 or rule uuid."""
    sha256 = sha256.lower()
    if not _SHA256_PATTERN.match(sha256):
        raise HTTPException(status_code=400, detail="invalid sha256")
    if not SIGNATURE_UUID_PATTERN.match(rule_uuid):
        raise HTTPException(status_code=400, detail="invalid rule uuid")
    return sha256


#
# GET /svs/samples: the listing, paged by keyset on (sort value, sha256, rule_uuid), never by
# offset. The statement is built once per request (relative dates resolve then) and each page runs
# in its own thread.
#

@dataclass(frozen=True)
class SampleListing:
    """A prepared listing: the filtered statement over samples (a samples_subquery()), with no order
    or limit, and the order its pages follow."""

    samples: Any
    statement: Select
    sort: SampleSort
    descending: bool


def _filter_entries(filter_params: list[str]) -> list[dict]:
    try:
        entries, _ = decode_filter_query(filter_params, screen=SVS_SAMPLES_SCREEN, strict=True)
    except FilterQueryError as e:
        raise InvalidListingRequest(str(e))

    try:
        return [entry.model_dump() for entry in SVS_SAMPLES_SCREEN.validate_entries(entries)]
    except ValidationError as e:
        raise InvalidListingRequest(e.errors(include_url=False, include_context=False))


def prepare_sample_listing(
    filter_params: list[str], *, sort: SampleSort, descending: bool, changed_since: datetime | None, tz
) -> SampleListing:
    """Builds the listing statement from share-link filters (`f=`) of the samples screen. Raises
    InvalidListingRequest."""
    entries = _filter_entries(filter_params)
    samples = samples_subquery()
    statement = select(samples)
    for condition in sample_filter_conditions(samples, entries, tz):
        statement = statement.where(condition)

    if changed_since is not None:
        statement = statement.where(changed_since_condition(samples, changed_since))

    return SampleListing(samples=samples, statement=statement, sort=sort, descending=descending)


def encode_listing_cursor(listing: SampleListing, key: list) -> str:
    payload = json.dumps({"v": _CURSOR_VERSION, "o": listing.sort.value, "d": listing.descending, "k": key},
                         separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def decode_listing_cursor(cursor: str, listing: SampleListing) -> list:
    """The keyset values a cursor carries. Raises InvalidCursor."""
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()))
        if payload["v"] != _CURSOR_VERSION:
            raise InvalidCursor(f"unsupported cursor version {payload['v']!r}")
        if payload["o"] != listing.sort.value or bool(payload["d"]) != listing.descending:
            raise InvalidCursor(
                f"this cursor pages a listing sorted by {payload['o']} ({'desc' if payload['d'] else 'asc'}): "
                "pass the same sort and desc as the request that returned it")
        return parse_sort_key(payload["k"], listing.sort)
    except InvalidCursor:
        raise
    except Exception as e:
        raise InvalidCursor(f"malformed cursor: {e}") from None


def _to_rows(records: list[dict]) -> list[SampleRow]:
    nodes = bytes_nodes(record["sha256"] for record in records)
    return [SampleRow(**sample_record(record), local=is_local(nodes.get(record["sha256"]))) for record in records]


def fetch_sample_page(listing: SampleListing, cursor: str | None, limit: int) -> tuple[list[SampleRow], str | None]:
    """One page of the listing after `cursor` (the first page when None), and the cursor of the
    next page (None on the last). Raises InvalidCursor."""
    statement = listing.statement
    if cursor is not None:
        key = decode_listing_cursor(cursor, listing)
        statement = statement.where(keyset_condition(listing.samples, listing.sort, listing.descending, key))

    statement = statement.order_by(*order_by(listing.samples, listing.sort, listing.descending)).limit(limit + 1)
    records = [dict(row) for row in get_db().execute(statement).mappings()]
    next_cursor = None
    if len(records) > limit:
        records = records[:limit]
        next_cursor = encode_listing_cursor(listing, sort_key(records[-1], listing.sort))

    return _to_rows(records), next_cursor


def sample_rows_to_csv(rows: list[SampleRow], *, header: bool) -> str:
    """CSV text for rows of the export, with the header line when asked; the votes are flattened."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    if header:
        writer.writerow(SAMPLE_ROW_CSV_FIELDS)
    for row in rows:
        values = row.model_dump(mode="json")
        values.update(values.pop("votes"))
        writer.writerow([values[name] if values[name] is not None else "" for name in SAMPLE_ROW_CSV_FIELDS])
    return buffer.getvalue()


#
# one sample
#

def _capture(row: SVSYaraCapture, detections: list[dict]) -> SampleCapture:
    return SampleCapture(
        id=row.id, alert_uuid=row.alert_uuid, observable_uuid=row.observable_uuid, rule_name=row.rule_name,
        namespace=row.namespace, signature_version=row.signature_version, rule_content_hash=row.rule_content_hash,
        file_path=row.file_path, file_size=row.file_size,
        yara_meta_tags=parse_json_column(row.yara_meta_tags, []), state=row.state,
        missing_reason=row.missing_reason, has_record=row.record_digest is not None,
        match_summary=parse_json_column(row.match_summary, {}),
        yara_python_version=row.yara_python_version, yara_scanner_version=row.yara_scanner_version,
        node=row.node, local=is_local(row.node), created_at=row.created_at, stored_at=row.stored_at,
        updated_at=row.updated_at,
        detections=[SampleDetection(**{name: detection[name] for name in SampleDetection.model_fields})
                    for detection in detections])


def _require_sample(sha256: str, rule_uuid: str) -> dict:
    record = get_sample(sha256, rule_uuid)
    if record is None:
        raise HTTPException(status_code=404, detail="sample not found")
    return record


def get_sample_detail(sha256: str, rule_uuid: str) -> SampleDetail:
    sha256 = validate_sample_key(sha256, rule_uuid)
    record = _require_sample(sha256, rule_uuid)
    captures = get_captures(sha256, rule_uuid)
    detections = contributing_detections(row.id for row in captures)
    node = bytes_nodes([sha256]).get(sha256)
    return SampleDetail(
        **record, local=is_local(node),
        captures=[_capture(row, detections.get(row.id, [])) for row in captures])


def missing_summary() -> list[MissingCount]:
    return [MissingCount(**record) for record in missing_by_rule()]


#
# match records
#

def resolve_record(capture_id: int) -> SVSYaraCapture:
    """The capture whose match record this node can serve. 404 without one, 409 wrong_node when it
    is on another node's local pool.

    With a local pool the record is taken to be on the capture's node. That is wrong in one case:
    a capture whose file was gone, which held another node's copy of the bytes and so records that
    node, wrote its record on its own node. A multi-node site does not use a local pool
    (docs/SVS_SAMPLES.md, *Nodes*)."""
    row = get_capture(capture_id)
    if row is None:
        raise HTTPException(status_code=404, detail="capture not found")
    if row.record_digest is None:
        raise HTTPException(status_code=404, detail="this capture has no match record")
    if not is_local(row.node):
        _raise_wrong_node(row.node, f"the match record of capture {row.id}")
    get_db().expunge(row)
    return row


def materialize_record(row: SVSYaraCapture) -> str:
    """The match record in a private temp file; the caller removes it."""
    fd, path = tempfile.mkstemp(prefix=f"svs-capture-record-{row.id}-", suffix=".json", dir=get_temp_dir())
    os.close(fd)
    os.remove(path)  # materialize() requires that the destination does not exist
    try:
        get_cas().pool(_pool_name()).materialize(row.record_digest, path)
    except ObjectNotFound:
        raise HTTPException(status_code=404, detail="the match record is no longer stored") from None

    return path


#
# downloads
#

@dataclass(frozen=True)
class SampleDownload:
    """What a download zips: per file, the samples of it that were selected and their captures."""
    # sha256 -> the node with its bytes, for the files this node can serve
    local: dict[str, Optional[str]]
    # sha256 -> the node with its bytes, for the files on another node's local pool
    remote: dict[str, Optional[str]]
    # sha256 -> the selected sample rows of that file
    samples: dict[str, list[dict]]
    # (sha256, rule_uuid) -> its stored captures, newest first
    captures: dict[tuple[str, str], list[SVSYaraCapture]]

    @property
    def sha256s(self) -> list[str]:
        return sorted(self.local)


def _download(records: list[dict]) -> SampleDownload:
    samples: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        samples[record["sha256"]].append(record)

    nodes = bytes_nodes(samples)
    local = {sha256: node for sha256, node in nodes.items() if is_local(node)}
    remote = {sha256: node for sha256, node in nodes.items() if not is_local(node)}

    captures: dict[tuple[str, str], list[SVSYaraCapture]] = defaultdict(list)
    pairs = [(record["sha256"], record["rule_uuid"]) for record in records]
    if pairs:
        rows = get_db().execute(
            select(SVSYaraCapture)
            .where(tuple_(SVSYaraCapture.sha256, SVSYaraCapture.rule_uuid).in_(pairs))
            .where(SVSYaraCapture.state == CaptureState.STORED)
            .order_by(SVSYaraCapture.id.desc())).scalars().all()
        for row in rows:
            get_db().expunge(row)
            captures[(row.sha256, row.rule_uuid)].append(row)

    return SampleDownload(local=local, remote=remote, samples=dict(samples), captures=dict(captures))


def resolve_sample_download(sha256: str, rule_uuid: str) -> SampleDownload:
    """One sample's file and its match records. 404 when it has no stored file, 409 wrong_node when
    the file is on another node's local pool."""
    sha256 = validate_sample_key(sha256, rule_uuid)
    download = _download([_require_sample(sha256, rule_uuid)])
    if download.remote:
        _raise_wrong_node(download.remote[sha256], f"sample {sha256}")
    if not download.local:
        raise HTTPException(status_code=404, detail="no capture of this sample holds its file")
    return download


def resolve_bulk_download(filter_params: list[str], *, tz) -> SampleDownload:
    """The files of every sample the filters match, with their match records, after enforcing the
    bulk limits on the files this node can serve: svs.samples.max_bulk_download_files distinct
    files and max_bulk_download_bytes bytes (413 past either). Files on another node's local pool
    are listed in the manifest as skipped. Raises InvalidListingRequest."""
    config = get_config().svs.samples
    listing = prepare_sample_listing(filter_params, sort=SampleSort.SHA256, descending=False,
                                     changed_since=None, tz=tz)
    samples = listing.samples
    selected = listing.statement.where(samples.c.stored > 0)

    # one more than the limit is enough to know it was exceeded
    sha256s = get_db().execute(
        select(selected.subquery().c.sha256).distinct().limit(config.max_bulk_download_files + 1)).scalars().all()
    if not sha256s:
        raise HTTPException(status_code=404, detail="no stored samples to download")
    if len(sha256s) > config.max_bulk_download_files:
        raise HTTPException(status_code=413, detail=(
            f"more than {config.max_bulk_download_files} files; narrow the download with filters"))

    records = [dict(row) for row in get_db().execute(
        selected.where(samples.c.sha256.in_(sha256s))
        .order_by(*order_by(samples, SampleSort.SHA256, False))).mappings()]
    download = _download(records)
    if not download.local:
        first = sorted(download.remote)[0]
        _raise_wrong_node(download.remote[first], f"sample {first}")

    total_bytes = sum(_file_size(download, sha256) for sha256 in download.local)
    if total_bytes > config.max_bulk_download_bytes:
        raise HTTPException(status_code=413, detail=(
            f"{total_bytes} bytes is more than {config.max_bulk_download_bytes}; narrow the download with filters"))

    return download


def _file_size(download: SampleDownload, sha256: str) -> int:
    return max((record["file_size"] or 0 for record in download.samples[sha256]), default=0)


def _record_name(capture: SVSYaraCapture) -> str:
    return f"match-{capture.id}.json"


def _manifest_samples(download: SampleDownload, sha256: str, record_paths: dict[int, str]) -> list[dict]:
    return [{
        "rule_uuid": record["rule_uuid"], "rule_name": record["rule_name"],
        "label": record["label"], "label_source": record["label_source"],
        "captures": [{
            "capture_id": capture.id, "alert_uuid": capture.alert_uuid,
            "signature_version": capture.signature_version, "file_path": capture.file_path,
            "match_record": record_paths.get(capture.id),
        } for capture in download.captures.get((sha256, record["rule_uuid"]), [])],
    } for record in download.samples[sha256]]


def create_sample_zip(label: str, download: SampleDownload, actor: Optional[str]) -> tuple[str, str]:
    """Zip the files and their match records, encrypted with the password infected
    (aceapi_v2/common/archive.py). Returns (zip path, staging directory); the caller removes the
    staging directory, which holds the zip.

    Layout, under one top-level directory named after label:
        manifest.json                     the samples in the zip, and what was skipped and why
        <sha256>/<file name>              the file once, under a sanitized version of its name
        <sha256>/match-<capture id>.json  the match record of each capture of a selected sample

    A capture's match record is included when this node can read it (see resolve_record)."""
    entries, skipped = [], []
    for sha256 in download.sha256s:
        captures = [capture for record in download.samples[sha256]
                    for capture in download.captures.get((sha256, record["rule_uuid"]), [])]
        records = [capture for capture in captures if capture.record_digest is not None and is_local(capture.node)]
        record_names = {capture.id: _record_name(capture) for capture in records}
        latest = max(captures, key=lambda capture: capture.id, default=None)
        file_name = safe_file_name(
            os.path.basename(latest.file_path) if latest is not None else download.samples[sha256][0]["file_path"],
            reserved={MANIFEST_NAME, *record_names.values()})

        manifest = {"sha256": sha256, "file_size": _file_size(download, sha256),
                    "samples": _manifest_samples(download, sha256, {})}
        entries.append(CASArchiveEntry(
            directory=sha256,
            members=((file_name, sha256),
                     *((record_names[capture.id], capture.record_digest) for capture in records)),
            manifest=manifest,
            included={**manifest, "path": f"{sha256}/{file_name}",
                      "samples": _manifest_samples(
                          download, sha256, {capture_id: f"{sha256}/{name}" for capture_id, name in record_names.items()})}))

    for sha256, node in sorted(download.remote.items()):
        skipped.append({"sha256": sha256, "node": node, "samples": _manifest_samples(download, sha256, {}),
                        "reason": "wrong_node"})

    return create_encrypted_cas_zip(
        label, get_cas().pool(_pool_name()), entries, skipped,
        manifest_key="files", description=f"svs samples {label}", actor=actor, node=_local_node())
