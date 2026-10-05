import itertools
import uuid
from datetime import datetime, timedelta
from typing import Optional

import pytest
from sqlalchemy import select, update

from saq.cas import CASPool, get_cas
from saq.database.model import YaraQAMatch, YaraQASignature
from saq.database.private_session import private_transaction

QA_UUID = "5a0c7f1e-1c43-4a39-8d8e-2f1b3c4d5e6f"
VERSION_A = "a" * 40
VERSION_B = "b" * 40
VERSION_C = "c" * 40


def qa_match_result(signature_uuid: Optional[str] = QA_UUID, commit: Optional[str] = VERSION_A,
                    rule: str = "qa_rule", strings: Optional[list] = None) -> dict:
    """A match dict shaped the way yara_scanner returns one."""
    meta = {"modifiers": "qa", "author": "unittest"}
    if signature_uuid is not None:
        meta["uuid"] = signature_uuid

    return {
        "target": "/tmp/scan.target",
        "rule": rule,
        "namespace": "/opt/ace/signatures/yara/unittest",
        "commit": commit,
        "tags": ["unittest"],
        "meta": meta,
        "strings": strings if strings is not None else [(0, "$a", b"abc"), (10, "$a", b"abc"), (5, "$b", b"\x00x")],
    }


@pytest.fixture
def qa_pool() -> CASPool:
    return get_cas().pool("yara_qa")


@pytest.fixture
def make_file(root_analysis, tmp_path):
    """A file observable in root_analysis with unique content (or the content given)."""
    counter = itertools.count()

    def _make(content: Optional[bytes] = None, name: Optional[str] = None):
        n = next(counter)
        if content is None:
            content = f"qa sample {n} {uuid.uuid4()}".encode()

        path = tmp_path / (name or f"sample_{n}.bin")
        path.write_bytes(content)
        return root_analysis.add_file_observable(str(path))

    return _make


def match_rows(signature_uuid: str = QA_UUID) -> list[YaraQAMatch]:
    with private_transaction() as session:
        rows = session.execute(
            select(YaraQAMatch).where(YaraQAMatch.signature_uuid == signature_uuid).order_by(YaraQAMatch.id)
        ).scalars().all()
        session.expunge_all()
        return rows


def counter_row(signature_version: str = VERSION_A, signature_uuid: str = QA_UUID) -> Optional[YaraQASignature]:
    with private_transaction() as session:
        row = session.get(YaraQASignature, (signature_uuid, signature_version))
        session.expunge_all()
        return row


def expire_matches(ids: list[int]) -> None:
    """Move the rows' expiry into the past, as the database sees time."""
    with private_transaction() as session:
        session.execute(
            update(YaraQAMatch).where(YaraQAMatch.id.in_(ids))
            .values(expires_at=datetime.now() - timedelta(days=1))
            .execution_options(synchronize_session=False))
