import json
import uuid
from datetime import datetime
from typing import Optional

import pytest
from sqlalchemy import select, update

from saq.analysis.root import RootAnalysis
from saq.cas import CASPool, get_cas
from saq.database.model import Alert, SVSYaraCapture, load_alert
from saq.database.pool import get_db
from saq.database.util.alert import ALERT
from saq.environment import get_global_runtime_settings
from saq.modules.file_analysis.yara import YaraScanResults_v3_4
from saq.observables.file import FileObservable
from saq.signatures.builtin import YARA_RULE_MATCH
from saq.signatures.model import SignatureType
from saq.database.private_session import private_transaction
from saq.svs.constants import CaptureState
from tests.saq.helpers import create_root_analysis

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


def insert_capture(alert_uuid: str, sha256: str, rule_uuid: str = RULE_UUID, **values) -> int:
    """Writes a capture row as saq.svs.capture would leave it (stored, with no CAS objects unless
    the caller put them), for tests that read samples. Returns its id."""
    row = dict(
        alert_uuid=alert_uuid, observable_uuid=str(uuid.uuid4()), sha256=sha256, rule_uuid=rule_uuid,
        rule_name="svs_rule", namespace="unittest", signature_version=COMMIT, file_path="sample.bin",
        file_size=10, yara_meta_tags=json.dumps([]), node=get_global_runtime_settings().saq_node,
        # created_at is a whole-second DATETIME, which rounds: a capture written with microseconds
        # could land in the future of a "-7d" filter's "now"
        state=CaptureState.STORED, created_at=datetime.now().replace(microsecond=0),
        stored_at=datetime.now().replace(microsecond=0))
    row.update(values)
    with private_transaction() as session:
        capture = SVSYaraCapture(**row)
        session.add(capture)
        session.flush()
        return capture.id


def set_disposition(alert_uuid: str, disposition: Optional[str]):
    get_db().execute(update(Alert).where(Alert.uuid == alert_uuid).values(disposition=disposition))
    get_db().commit()
    get_db().expire_all()


def graded_alert(disposition: Optional[str], files: dict[str, list[str]], *, capture: bool = True,
                 contents: Optional[dict[str, bytes]] = None):
    """An alert whose file observables YARA matched, synced, with its disposition set and (unless
    capture=False) a capture row per (file sha256, rule uuid). files maps a file name to the rule
    uuids that matched it; contents optionally gives a file's bytes (the same bytes under two names
    are one sha256). Returns (alert, {name: file observable})."""
    root = create_root_analysis(uuid=str(uuid.uuid4()))
    root.initialize_storage()
    observables = {}
    for name, rule_uuids in files.items():
        observables[name] = add_file(root, name, (contents or {}).get(name))
        for index, rule_uuid in enumerate(rule_uuids):
            add_yara_match(observables[name], rule=f"svs_rule_{index}", rule_uuid=rule_uuid)

    root.save()
    ALERT(root)
    set_disposition(root.uuid, disposition)

    if capture:
        seen = set()
        for name, rule_uuids in files.items():
            for rule_uuid in rule_uuids:
                key = (observables[name].value.lower(), rule_uuid)
                if key not in seen:
                    seen.add(key)
                    insert_capture(root.uuid, key[0], rule_uuid, file_path=name)

    return load_alert(root.uuid), observables
