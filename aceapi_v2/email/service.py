"""Archived email service for ACE API v2."""

import asyncio
from collections.abc import Iterator
from typing import Optional

from saq.email_archive import get_archived_email_path, iter_decrypt_email
from saq.environment import get_global_runtime_settings


class EncryptionKeyMissing(Exception):
    """Archived emails are stored encrypted and this node has no key to decrypt them with."""


async def open_archived_email(message_id: str) -> Optional[Iterator[bytes]]:
    """Returns an iterator over the decrypted bytes of the archived email with this Message-ID, or
    None if no such email is archived.

    The lookup runs here so that an unknown Message-ID can still be answered with a 404. The
    decryption runs when the iterator is first read, after the response has started, so a failure
    there truncates the download rather than changing its status.
    """
    if not get_global_runtime_settings().encryption_key:
        raise EncryptionKeyMissing()

    # the lookup is a query against the email archive database on a sync connection
    target_path = await asyncio.to_thread(get_archived_email_path, message_id)
    if target_path is None:
        return None

    return iter_decrypt_email(target_path)
