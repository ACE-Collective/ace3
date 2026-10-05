import uuid
from typing import Optional

import pytest
from sqlalchemy import select

from saq.analysis.root import RootAnalysis
from saq.cas import CASPool, get_cas
from saq.database.model import SVSYaraCapture
from saq.modules.file_analysis.yara import YaraScanResults_v3_4
from saq.observables.file import FileObservable
from saq.signatures.builtin import YARA_RULE_MATCH
from saq.signatures.model import SignatureType
from saq.database.private_session import private_transaction

RULE_UUID = "7d1c2a4e-5b6f-4c3d-9e8f-0a1b2c3d4e5f"
OTHER_RULE_UUID = "1e2d3c4b-5a69-4788-9a0b-1c2d3e4f5a6b"
COMMIT = "c" * 40


def scan_result(rule: str = "svs_rule", rule_uuid: Optional[str] = RULE_UUID, commit: Optional[str] = COMMIT) -> dict:
    """A scan_results entry as an alert's saved JSON has it: the strings were (offset, identifier,
    bytes) when scanned and are lists of str once saved."""
    meta = {"author": "unittest"}
    if rule_uuid is not None:
        meta["uuid"] = rule_uuid

    return {
        "target": "/tmp/scan.target",
        "rule": rule,
        "namespace": "/opt/ace/signatures/yara/unittest",
        "commit": commit,
        "tags": ["unittest"],
        "meta": meta,
        "strings": [[0, "$a", "abc"], [10, "$a", "abc"], [5, "$b", "\x00x"]],
    }


def add_file(root: RootAnalysis, name: str = "sample.bin", content: Optional[bytes] = None) -> FileObservable:
    if content is None:
        content = f"svs sample {uuid.uuid4()}".encode()

    path = root.create_file_path(name)
    with open(path, "wb") as fp:
        fp.write(content)

    return root.add_file_observable(path)


def add_yara_match(file_observable: FileObservable, rule: str = "svs_rule", rule_uuid: Optional[str] = RULE_UUID,
                   commit: Optional[str] = COMMIT, namespace: str = "unittest", record: bool = True):
    """What the YARA module leaves in the tree for one match: the scan_results entry, and the
    detection on the file with its structured details."""
    analysis = file_observable.get_and_load_analysis(YaraScanResults_v3_4)
    if analysis is None:
        analysis = file_observable.add_analysis(YaraScanResults_v3_4())

    if record:
        analysis.scan_results.append(scan_result(rule, rule_uuid, commit))

    file_observable.add_detection_point(
        f"{file_observable} matched yara rule {rule}",
        details={"sha256": file_observable.value.lower(), "rule": rule, "namespace": namespace, "rule_uuid": rule_uuid},
        signature_uuid=rule_uuid or YARA_RULE_MATCH.uuid,
        signature_version=commit or "unknown",
        signature_family=SignatureType.YARA.value if rule_uuid else None)


def capture_rows(alert_uuid: Optional[str] = None) -> list[SVSYaraCapture]:
    with private_transaction() as session:
        query = select(SVSYaraCapture).order_by(SVSYaraCapture.id)
        if alert_uuid is not None:
            query = query.where(SVSYaraCapture.alert_uuid == alert_uuid)

        rows = session.execute(query).scalars().all()
        session.expunge_all()
        return rows


@pytest.fixture
def svs_pool() -> CASPool:
    return get_cas().pool("svs_samples")
