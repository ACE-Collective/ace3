"""Archived email service for ACE API v2."""

import io
from collections.abc import Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from typing import BinaryIO, Optional

from fastapi import HTTPException

from aceapi_v2.common.archive import CASArchiveEntry, create_encrypted_cas_zip, safe_file_name
from aceapi_v2.email.schemas import ArchivedEmailCopy, ArchiveLookupResult
from aceapi_v2.sync import run_db_in_thread
from saq.cas.errors import ObjectNotFound
from saq.configuration.config import get_config
from saq.email import normalize_message_id
from saq.email_archive import find_archived_email, get_email_archive_pool, query_archived_copies
from saq.environment import get_global_runtime_settings


class EncryptionKeyMissing(Exception):
    """Archived emails are stored encrypted and this node has no key to decrypt them with."""


def lookup_archived_emails(message_ids: list[str]) -> list[ArchiveLookupResult]:
    """Every archived copy of each Message-ID, in request order. Batched, never per Message-ID:
    the archive's rows, then which of those emails the pool still has."""
    copies = query_archived_copies(message_ids)
    digests = list(dict.fromkeys(copy.digest for found in copies.values() for copy in found))
    sizes = get_email_archive_pool().sizes(digests)

    results = []
    for index, message_id in enumerate(message_ids):
        normalized = normalize_message_id(message_id)
        found = copies.get(normalized, [])
        results.append(ArchiveLookupResult(
            index=index,
            message_id=normalized,
            copies=[ArchivedEmailCopy(sha256=copy.digest, archived_at=copy.archived_at, size=sizes[copy.digest])
                    for copy in found if copy.digest in sizes],
            expired_copies=sum(1 for copy in found if copy.digest not in sizes)))

    return results


def require_encryption_key() -> None:
    if not get_global_runtime_settings().encryption_key:
        raise EncryptionKeyMissing()


@dataclass(frozen=True)
class ArchiveDownload:
    """What a POST /email/archive/download zip will hold."""
    entries: list[CASArchiveEntry]
    skipped: list[dict]
    # each email once, in request order
    sha256s: list[str]


def resolve_download(message_ids: list[str]) -> ArchiveDownload:
    """Every archived copy of each Message-ID, after enforcing email_archive.max_bulk_download_files
    and max_bulk_download_bytes on the files the zip will hold (413 past either). 404 when no
    Message-ID has an archived email."""
    config = get_config().email_archive
    results = lookup_archived_emails(message_ids)
    members = [copy for result in results for copy in result.copies]
    if not members:
        raise HTTPException(status_code=404, detail="none of the Message-IDs has an archived email")
    if len(members) > config.max_bulk_download_files:
        raise HTTPException(status_code=413, detail=(
            f"{len(members)} emails is more than {config.max_bulk_download_files}; download fewer Message-IDs at a time"))
    total_bytes = sum(copy.size for copy in members)
    if total_bytes > config.max_bulk_download_bytes:
        raise HTTPException(status_code=413, detail=(
            f"{total_bytes} bytes is more than {config.max_bulk_download_bytes}; download fewer Message-IDs at a time"))

    entries, skipped = [], []
    for result in results:
        described = {"index": result.index, "message_id": result.message_id}
        if not result.copies:
            skipped.append({**described, "reason": "expired" if result.expired_copies else "not_archived"})
            continue

        # the index keeps two Message-IDs that clean to the same name apart, so it stays outside
        # safe_file_name(), which keeps only what follows the last "/" (a Message-ID may have one)
        directory = f"{result.index:04d}-{safe_file_name(result.message_id.replace('/', '_'))}"
        copies = [{"sha256": copy.sha256, "archived_at": copy.archived_at.isoformat(), "size": copy.size}
                  for copy in result.copies]
        entries.append(CASArchiveEntry(
            directory=directory,
            members=tuple((f"{copy.sha256}.eml", copy.sha256) for copy in result.copies),
            manifest={**described, "copies": copies},
            included={**described, "copies": [{**copy, "path": f"{directory}/{copy['sha256']}.eml"} for copy in copies]}))

    return ArchiveDownload(entries=entries, skipped=skipped, sha256s=list(dict.fromkeys(copy.sha256 for copy in members)))


def create_download_zip(label: str, download: ArchiveDownload, actor: Optional[str]) -> tuple[str, str]:
    """Zip the emails, encrypted with the password infected (aceapi_v2/common/archive.py). Returns
    (zip path, staging directory); the caller removes the staging directory, which holds the zip.

    Layout, under one top-level directory named after label:
        manifest.json                           the emails in the zip, and what was skipped and why
        <index>-<message id>/<sha256>.eml       each email of each Message-ID, the index its
                                                position in the request"""
    return create_encrypted_cas_zip(
        label, get_email_archive_pool(), download.entries, download.skipped,
        manifest_key="emails", description=f"archived emails {label}", actor=actor,
        node=get_global_runtime_settings().saq_node)


def _open_digest(digest: str) -> Optional[tuple[ExitStack, BinaryIO]]:
    # the pool verifies (and decrypts) the email before open() returns, so everything that touches
    # the database happens here, in run_db_in_thread, and the response only reads an open file
    stack = ExitStack()
    try:
        fp = stack.enter_context(get_email_archive_pool().open(digest))
    except ObjectNotFound:
        # never archived, expired, or collected since it was looked up. The pool has already
        # reported bytes missing under a present row
        stack.close()
        return None
    except BaseException:
        stack.close()
        raise

    return stack, fp


def _open(message_id: str) -> Optional[tuple[ExitStack, BinaryIO]]:
    digest = find_archived_email(message_id)
    if digest is None:
        return None

    return _open_digest(digest)


def _iter_file(stack: ExitStack, fp: BinaryIO) -> Iterator[bytes]:
    with stack:
        while True:
            data = fp.read(io.DEFAULT_BUFFER_SIZE)
            if not data:
                break

            yield data


async def open_archived_email(message_id: str) -> Optional[Iterator[bytes]]:
    """Returns an iterator over the decrypted bytes of the archived email with this Message-ID, or
    None if no such email is archived (or it has expired from the archive).

    The email is looked up and verified before this returns, so an unknown Message-ID is a 404 and
    a corrupt email fails the request instead of truncating the download.
    """
    require_encryption_key()
    opened = await run_db_in_thread(_open, message_id)
    if opened is None:
        return None

    return _iter_file(*opened)


async def open_archived_copy(digest: str) -> Optional[Iterator[bytes]]:
    """open_archived_email() for one archived email named by its sha256, whichever Message-ID it
    was archived under: the way to read a copy other than the newest."""
    require_encryption_key()
    opened = await run_db_in_thread(_open_digest, digest)
    if opened is None:
        return None

    return _iter_file(*opened)
