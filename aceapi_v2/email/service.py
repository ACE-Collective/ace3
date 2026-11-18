"""Archived email service for ACE API v2."""

import io
from collections.abc import Iterator
from contextlib import ExitStack
from typing import BinaryIO, Optional

from aceapi_v2.sync import run_db_in_thread
from saq.email_archive import find_archived_email, get_email_archive_pool
from saq.environment import get_global_runtime_settings


class EncryptionKeyMissing(Exception):
    """Archived emails are stored encrypted and this node has no key to decrypt them with."""


def _open(message_id: str) -> Optional[tuple[ExitStack, BinaryIO]]:
    digest = find_archived_email(message_id)
    if digest is None:
        return None

    # the pool verifies (and decrypts) the email before open() returns, so everything that touches
    # the database happens here, in run_db_in_thread, and the response only reads an open file
    stack = ExitStack()
    try:
        fp = stack.enter_context(get_email_archive_pool().open(digest))
    except BaseException:
        stack.close()
        raise

    return stack, fp


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
    if not get_global_runtime_settings().encryption_key:
        raise EncryptionKeyMissing()

    opened = await run_db_in_thread(_open, message_id)
    if opened is None:
        return None

    return _iter_file(*opened)
