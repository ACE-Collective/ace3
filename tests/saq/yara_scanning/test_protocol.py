import json
import socket
import struct

import pytest

from saq.yara_scanning import protocol
from saq.yara_scanning.protocol import ConnectionClosedError, ProtocolError


@pytest.fixture
def pair():
    a, b = socket.socketpair()
    yield a, b
    a.close()
    b.close()


@pytest.mark.unit
def test_frame_round_trip(pair):
    a, b = pair
    protocol.send_frame(a, b"\x00\xffbinary")
    protocol.send_frame(a, b"")
    assert protocol.recv_frame(b, 1024) == b"\x00\xffbinary"
    assert protocol.recv_frame(b, 1024) == b""


@pytest.mark.unit
def test_short_read_raises(pair):
    a, b = pair
    a.sendall(struct.pack("!I", 10) + b"abc")
    a.close()
    with pytest.raises(ConnectionClosedError):
        protocol.recv_frame(b, 1024)


@pytest.mark.unit
def test_closed_before_length_raises(pair):
    a, b = pair
    a.close()
    with pytest.raises(ConnectionClosedError):
        protocol.recv_frame(b, 1024)


@pytest.mark.unit
def test_oversized_frame_raises(pair):
    a, b = pair
    protocol.send_frame(a, b"x" * 100)
    with pytest.raises(ProtocolError):
        protocol.recv_frame(b, 99)


@pytest.mark.unit
@pytest.mark.parametrize("payload", [b"not json", b"[1, 2]"])
def test_recv_json_rejects_non_objects(pair, payload):
    a, b = pair
    protocol.send_frame(a, payload)
    with pytest.raises(ProtocolError):
        protocol.recv_json(b, 1024)


@pytest.mark.unit
def test_matches_round_trip_through_json():
    matches = [{
        "target": "/path/to/file",
        "meta": {"uuid": "1234", "modifiers": "qa", "score": 5, "enabled": True},
        "namespace": "rules",
        "commit": None,
        "rule": "test_rule",
        "strings": [(0, "$a", b"\x00\xff\xfe"), (42, "$b", b"text")],
        "tags": ["tag"],
    }]

    decoded = protocol.decode_matches(json.loads(json.dumps(protocol.encode_matches(matches))))
    assert decoded == matches
    assert all(isinstance(entry, tuple) for entry in decoded[0]["strings"])


@pytest.mark.unit
@pytest.mark.parametrize("matches", [
    {"not": "a list"},
    ["not a dict"],
    [{"rule": "r", "strings": [[0, "$a", "not base64!"]]}],
    [{"rule": "r", "strings": [["x", "$a", ""]]}],
])
def test_decode_matches_rejects_invalid(matches):
    with pytest.raises(ProtocolError):
        protocol.decode_matches(matches)


VALID_FILE_REQUEST = {"v": protocol.PROTOCOL_VERSION, "op": protocol.OP_SCAN_FILE, "path": "/tmp/x",
                      "ext_vars": {}, "meta_tags": None, "timeout": 5}


VALID_QA = {
    "root_uuid": "0c8a1d5e-7b2f-4c1e-9a3d-5f6e7d8c9b0a",
    "observable_uuid": "1d9b2e6f-8c3a-4d2f-ab4e-6a7f8e9d0c1b",
    "file_name": "sample.bin",
    "file_size": 1024,
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}


@pytest.mark.unit
def test_valid_requests():
    assert protocol.validate_request(VALID_FILE_REQUEST) is None
    assert protocol.validate_request({"v": protocol.PROTOCOL_VERSION, "op": protocol.OP_SCAN_DATA}) is None
    assert protocol.validate_request({**VALID_FILE_REQUEST, "meta_tags": ["a", "b=c"]}) is None
    assert protocol.validate_request({**VALID_FILE_REQUEST, "qa": VALID_QA}) is None
    assert protocol.validate_request({**VALID_FILE_REQUEST, "qa": {**VALID_QA, "file_size": 0}}) is None


@pytest.mark.unit
@pytest.mark.parametrize("changes", [
    {"v": 2},
    {"op": "delete_everything"},
    {"path": ""},
    {"path": None},
    {"ext_vars": ["a"]},
    {"meta_tags": "a"},
    {"meta_tags": [1]},
    {"timeout": 0},
    {"timeout": True},
    {"timeout": "5"},
    {"qa": "yes"},
    {"qa": {**VALID_QA, "root_uuid": ""}},
    {"qa": {**VALID_QA, "observable_uuid": "x" * 37}},
    {"qa": {**VALID_QA, "file_name": ""}},
    {"qa": {**VALID_QA, "file_size": -1}},
    {"qa": {**VALID_QA, "file_size": True}},
    {"qa": {**VALID_QA, "sha256": "A" * 64}},
    {"qa": {**VALID_QA, "sha256": "a" * 63}},
    {"qa": {k: v for k, v in VALID_QA.items() if k != "sha256"}},
])
def test_invalid_requests(changes):
    assert protocol.validate_request({**VALID_FILE_REQUEST, **changes})


@pytest.mark.unit
def test_qa_is_only_valid_for_scan_file():
    request = {"v": protocol.PROTOCOL_VERSION, "op": protocol.OP_SCAN_DATA, "qa": VALID_QA}
    assert protocol.validate_request(request) == "qa is only valid for scan_file"
