"""The corpus a validation replays: every stored SVS capture, with the labels of its samples.

A **unit** is one way a file was scanned: a distinct (sha256, file_path, yara_meta_tags) over the
stored captures. The path decides the filename, filepath and extension externals and the
file_ext/file_name filters, and the tags decide the meta_tags filters, so the same bytes captured
under two names are scanned twice, and a rule matches the file if it matches any of its units.

A **sample** is one (sha256, rule uuid) and carries the label (saq.svs.labels). The samples and
the units are read in one transaction, so the labels are those of the same moment.

Each unit is written to `<files_root>/<n>/files/<file_path>`, the tail of the path the file had in
its alert's storage directory, by copying from the pool's open(). Never materialize(): it can
hardlink the pool's read cache, which the sandboxed scan would then be able to modify. A path that
is absolute or climbs out with `..` is not replayed, and nor are files whose bytes are on another
node's local pool.
"""

import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import select

from saq.cas.pool import CASPool
from saq.database.model import SVSYaraCapture
from saq.database.pool import get_db
from saq.svs.constants import CaptureState
from saq.svs.samples import is_local, samples_subquery

# svs_yara_captures.file_path is cut at this length when it is stored
FILE_PATH_MAX_LENGTH = 1024

SKIP_WRONG_NODE = "wrong_node"
SKIP_UNSAFE_PATH = "unsafe_path"
SKIP_UNREADABLE = "unreadable"


@dataclass(frozen=True)
class Sample:
    sha256: str
    rule_uuid: str
    rule_name: str
    label: Optional[str]
    label_source: Optional[str]


@dataclass
class Unit:
    id: int
    sha256: str
    file_path: str
    meta_tags: tuple[str, ...]
    # where it was written, once it was
    path: Optional[str] = None
    # the stored path was cut to FILE_PATH_MAX_LENGTH: the path externals may differ
    truncated: bool = False


@dataclass(frozen=True)
class Skipped:
    sha256: str
    file_path: Optional[str]
    reason: str
    detail: str = ""


@dataclass
class Corpus:
    samples: dict[tuple[str, str], Sample] = field(default_factory=dict)
    units: list[Unit] = field(default_factory=list)
    # sha256 -> the node that has its bytes
    nodes: dict[str, str] = field(default_factory=dict)
    skipped: list[Skipped] = field(default_factory=list)
    bytes: int = 0

    def replayed_sha256s(self) -> set[str]:
        return {unit.sha256 for unit in self.units if unit.path is not None}


def _meta_tags(value: Optional[str]) -> tuple[str, ...]:
    try:
        tags = json.loads(value) if value else []
    except ValueError:
        return ()

    return tuple(str(tag) for tag in tags) if isinstance(tags, list) else ()


def is_safe_path(file_path: str) -> bool:
    if not file_path or "\0" in file_path or os.path.isabs(file_path):
        return False

    return ".." not in file_path.split("/")


def read_corpus() -> Corpus:
    """Every stored unit and every sample, in one transaction of the caller's get_db() session."""
    corpus = Corpus()
    session = get_db()
    try:
        rows = session.execute(
            select(SVSYaraCapture.sha256, SVSYaraCapture.file_path, SVSYaraCapture.yara_meta_tags,
                   SVSYaraCapture.node)
            .where(SVSYaraCapture.state == CaptureState.STORED)
            .order_by(SVSYaraCapture.id)).all()

        samples = samples_subquery()
        sample_rows = session.execute(
            select(samples.c.sha256, samples.c.rule_uuid, samples.c.rule_name, samples.c.label,
                   samples.c.label_source)).all()
    finally:
        session.commit()

    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for row in rows:
        # the first stored capture of a file is where its bytes are (bytes_nodes_statement)
        corpus.nodes.setdefault(row.sha256, row.node)
        meta_tags = _meta_tags(row.yara_meta_tags)
        key = (row.sha256, row.file_path, meta_tags)
        if key in seen:
            continue

        seen.add(key)
        corpus.units.append(Unit(
            id=len(corpus.units), sha256=row.sha256, file_path=row.file_path, meta_tags=meta_tags,
            truncated=len(row.file_path) >= FILE_PATH_MAX_LENGTH))

    stored = set(corpus.nodes)
    for row in sample_rows:
        if row.sha256 in stored:
            corpus.samples[(row.sha256, row.rule_uuid)] = Sample(
                row.sha256, row.rule_uuid, row.rule_name, row.label, row.label_source)

    return corpus


def write_units(corpus: Corpus, pool: CASPool, files_root: str) -> None:
    """Write every unit this node can read under files_root; record the rest in corpus.skipped."""
    written: dict[str, str] = {}
    refused: set[str] = set()
    for unit in corpus.units:
        if unit.sha256 in refused:
            continue

        node = corpus.nodes.get(unit.sha256)
        if not is_local(node):
            refused.add(unit.sha256)
            corpus.skipped.append(Skipped(unit.sha256, None, SKIP_WRONG_NODE, f"its bytes are on node {node}"))
            continue

        if not is_safe_path(unit.file_path):
            corpus.skipped.append(Skipped(unit.sha256, unit.file_path, SKIP_UNSAFE_PATH))
            continue

        dest = os.path.join(files_root, str(unit.id), "files", unit.file_path)
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            source = written.get(unit.sha256)
            if source is not None:
                os.link(source, dest)
            else:
                with pool.open(unit.sha256) as fp_in, open(dest, "wb") as fp_out:
                    shutil.copyfileobj(fp_in, fp_out)

                written[unit.sha256] = dest
                corpus.bytes += os.path.getsize(dest)
        except Exception as e:
            logging.warning("unable to replay svs sample %s: %s", unit.sha256, e)
            if unit.sha256 not in written:
                refused.add(unit.sha256)
            corpus.skipped.append(Skipped(unit.sha256, unit.file_path, SKIP_UNREADABLE, str(e)))
            continue

        unit.path = dest
