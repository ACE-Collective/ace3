"""The corpus a validation replays (saq.svs.yara.corpus)."""

import hashlib
import json
import os
import uuid

import pytest

from saq.cas import get_cas
from saq.configuration.config import get_config
from saq.svs.capture import capture_hold
from saq.svs.constants import CaptureState
from saq.svs.yara.corpus import FILE_PATH_MAX_LENGTH, SKIP_UNREADABLE, SKIP_UNSAFE_PATH, SKIP_WRONG_NODE, read_corpus, write_units
from tests.saq.svs.conftest import OTHER_RULE_UUID, RULE_UUID, insert_capture
from tests.saq.svs.yara.conftest import stored_sample


def _pool():
    return get_cas().pool(get_config().svs.samples.pool)


def _put(content: bytes, capture_id: int):
    return _pool().put(content, hold=capture_hold(capture_id))


@pytest.mark.integration
def test_units_are_distinct_scans_and_samples_carry_labels():
    sha256 = stored_sample("DELIVERY", b"replay me", [RULE_UUID], name="invoice.pdf")
    # the same bytes under another name, and again under the same name and tags
    _put(b"replay me", insert_capture(str(uuid.uuid4()), sha256, OTHER_RULE_UUID, file_path="renamed.pdf"))
    _put(b"replay me", insert_capture(str(uuid.uuid4()), sha256, OTHER_RULE_UUID, file_path="invoice.pdf"))
    _put(b"replay me", insert_capture(str(uuid.uuid4()), sha256, OTHER_RULE_UUID, file_path="invoice.pdf",
                                      yara_meta_tags=json.dumps(["kind=email"])))
    # a capture that was never stored is no unit, and its file no sample
    insert_capture(str(uuid.uuid4()), "f" * 64, RULE_UUID, state=CaptureState.MISSING, missing_reason="file")

    corpus = read_corpus()
    assert sorted((unit.file_path, unit.meta_tags) for unit in corpus.units) == [
        ("invoice.pdf", ()), ("invoice.pdf", ("kind=email",)), ("renamed.pdf", ())]
    assert set(corpus.samples) == {(sha256, RULE_UUID), (sha256, OTHER_RULE_UUID)}
    assert corpus.samples[(sha256, RULE_UUID)].label == "tp"
    assert corpus.samples[(sha256, OTHER_RULE_UUID)].label is None


@pytest.mark.integration
def test_units_are_copied_out_of_the_pool(tmp_path):
    sha256 = stored_sample("FALSE_POSITIVE", b"copy me", [RULE_UUID], name="dir/a.txt")
    _put(b"copy me", insert_capture(str(uuid.uuid4()), sha256, OTHER_RULE_UUID, file_path="b.txt"))

    corpus = read_corpus()
    write_units(corpus, _pool(), str(tmp_path / "u"))

    paths = {unit.file_path: unit.path for unit in corpus.units}
    assert paths["dir/a.txt"].endswith("/files/dir/a.txt")
    for path in paths.values():
        with open(path, "rb") as fp:
            assert fp.read() == b"copy me"
    assert corpus.replayed_sha256s() == {sha256}
    assert corpus.bytes == len(b"copy me")
    assert corpus.skipped == []


@pytest.mark.integration
def test_what_cannot_be_replayed_is_skipped(tmp_path):
    other_node = insert_capture(str(uuid.uuid4()), "1" * 64, RULE_UUID, node="another-node")
    _put(b"elsewhere", other_node)
    unsafe = stored_sample("DELIVERY", b"unsafe", [RULE_UUID], name="ok.bin")
    _put(b"unsafe", insert_capture(str(uuid.uuid4()), unsafe, OTHER_RULE_UUID, file_path="../../escape.bin"))
    _put(b"unsafe", insert_capture(str(uuid.uuid4()), unsafe, OTHER_RULE_UUID, file_path="/etc/escape.bin"))
    # stored, but the pool does not have the bytes
    insert_capture(str(uuid.uuid4()), "2" * 64, RULE_UUID)
    # cut to the column's width when it was stored
    long_path = ("d/" * FILE_PATH_MAX_LENGTH)[:FILE_PATH_MAX_LENGTH - 1] + "x"
    long_sha256 = hashlib.sha256(b"long").hexdigest()
    _put(b"long", insert_capture(str(uuid.uuid4()), long_sha256, RULE_UUID, file_path=long_path))

    corpus = read_corpus()
    write_units(corpus, _pool(), str(tmp_path / "u"))

    skipped = {(item.sha256, item.file_path): item.reason for item in corpus.skipped}
    assert skipped[("1" * 64, None)] == SKIP_WRONG_NODE
    assert skipped[(unsafe, "../../escape.bin")] == SKIP_UNSAFE_PATH
    assert skipped[(unsafe, "/etc/escape.bin")] == SKIP_UNSAFE_PATH
    assert skipped[("2" * 64, "sample.bin")] == SKIP_UNREADABLE
    assert corpus.replayed_sha256s() == {unsafe, long_sha256}
    assert not os.path.exists(tmp_path / "escape.bin")
    assert [unit.truncated for unit in corpus.units if unit.sha256 == long_sha256] == [True]
