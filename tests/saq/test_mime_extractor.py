import os.path
import struct
import zlib

import pytest

from saq.mime_extractor import parse_mime, parse_active_mime
from saq.util import sha256

@pytest.mark.unit
def test_parse_mime(datadir, tmpdir):
    target_dir = str(tmpdir / "parsed_mime")
    extracted_files = parse_mime(str(datadir / "718148a5712c1fec7b50acc89eee2aa0"), target_dir)
    assert len(extracted_files) == 14
    assert sha256(os.path.join(target_dir, "extracted-0")) ==  "ce801838416da318a8a2f1e16d2314414427862bcfb473afda44f0217ec7fa2f"
    assert sha256(os.path.join(target_dir, "extracted-1")) ==  "65a1e83a2c052e128fa1e4bc2d0365b8bb2533945c14a10ae532aec371134a3d"
    assert sha256(os.path.join(target_dir, "extracted-10")) == "315108b38d5662aa4e9455ecd1b481a15acb292390dc86faf39e03c5e096056f"
    assert sha256(os.path.join(target_dir, "extracted-11")) == "8cd579f33b6bee18e2af4651192e21f802cc740eed38af9053ec690dcabf8efd"
    assert sha256(os.path.join(target_dir, "extracted-12")) == "f350d2f7839fe85fb477a02dab68d545a50772314e61113052f082685106f0a2"
    assert sha256(os.path.join(target_dir, "extracted-13")) == "0bea86356ad057bdaa7a53e13e47c264ca5e923fb6f7048e46a7a3860742e64f"
    assert sha256(os.path.join(target_dir, "extracted-2")) ==  "65f3cdbc4390c81b94fa960b7362917443fc1e6a51e3f81e4cb4c4dfa09da4be"
    assert sha256(os.path.join(target_dir, "extracted-3")) ==  "be8d780401ec0b5ae04d6b5a00d8d5998e0d3bd6598d03e645427c7feb288eaf"
    assert sha256(os.path.join(target_dir, "extracted-4")) ==  "85a1fb1026ae078efcb88f77e064ef874a4ef074d84f5d00232bab4ab60e75a8"
    assert sha256(os.path.join(target_dir, "extracted-5")) ==  "8044bfe6b5223c069e8632f91993c4ea082b30fb4c6371c00166199903bad833"
    assert sha256(os.path.join(target_dir, "extracted-6")) ==  "580e14734c48fd7239b88bdaf8546866c401d9580b05b82e7efc3906c7d1f248"
    assert sha256(os.path.join(target_dir, "extracted-7")) ==  "1908ce99e39b3abbed4819b32799023735ba6320a72e9eb1af49e303d2988b7d"
    assert sha256(os.path.join(target_dir, "extracted-8")) ==  "40e4e77b31bb3aa16458f2f0adbcbd8cc3308e7a2b1285733602b53f15675164"
    assert sha256(os.path.join(target_dir, "extracted-9")) ==  "d2e401681d96e46cac1c027ce0a02eb6b4b91096c014c3bc170d2025707b63d5"

@pytest.mark.unit
def test_parse_active_mime(datadir, tmpdir):
    target_path = str(tmpdir / "parsed")
    result = parse_active_mime(str(datadir / "extracted-12"), target_path)
    assert result
    assert sha256(target_path) == "d82f411152bcc9fdb41523528e5139cf3367650871462debbc17f2ac654d0b06"


SYNTHETIC_PAYLOAD = b"synthetic ole payload " * 50

def _build_active_mime(payload: bytes, field_size_e: int = 4) -> bytes:
    """Builds a minimal ActiveMime document with the same layout as a real one."""
    compressed = zlib.compress(payload)
    return (
        b"ActiveMime\x00\x00"
        + b"\x01\xf0"                              # unknown_a
        + struct.pack("<I", 4)                     # field_size
        + b"\xff\xff\xff\xff"                      # unknown_b
        + b"\x00\x00\x07\xf0"                      # unknown_c
        + struct.pack("<I", len(compressed))       # compressed_size
        + struct.pack("<I", 4)                     # field_size_d
        + struct.pack("<I", field_size_e)          # field_size_e
        + b"\x00\x00\x00\x00"                      # unknown_d
        + struct.pack("<I", 0)                     # vba_tail_type
        + struct.pack("<I", len(payload))          # size
        + compressed
    )

# offset of the compressed data in a blob built by _build_active_mime
_COMPRESSED_OFFSET = 50

def _parse_blob(tmpdir, blob: bytes) -> tuple[bool, str]:
    source_path = str(tmpdir / "activemime.bin")
    target_path = str(tmpdir / "parsed")
    with open(source_path, "wb") as fp:
        fp.write(blob)

    return parse_active_mime(source_path, target_path), target_path

@pytest.mark.unit
def test_parse_active_mime_synthetic_valid(tmpdir):
    result, target_path = _parse_blob(tmpdir, _build_active_mime(SYNTHETIC_PAYLOAD))
    assert result
    with open(target_path, "rb") as fp:
        assert fp.read() == SYNTHETIC_PAYLOAD

@pytest.mark.unit
def test_parse_active_mime_truncated(tmpdir):
    blob = _build_active_mime(SYNTHETIC_PAYLOAD)
    # every prefix that still passes the ActiveMime header check
    for length in range(len(b"ActiveMime"), len(blob)):
        result, target_path = _parse_blob(tmpdir, blob[:length])
        assert result is False, f"truncated at {length}"
        assert not os.path.exists(target_path)

@pytest.mark.unit
def test_parse_active_mime_bad_field_size_e(tmpdir):
    result, target_path = _parse_blob(tmpdir, _build_active_mime(SYNTHETIC_PAYLOAD, field_size_e=8))
    assert result is False
    assert not os.path.exists(target_path)

@pytest.mark.unit
@pytest.mark.parametrize("offset", [14, 30])  # field_size, field_size_d
def test_parse_active_mime_oversized_field_sizes(tmpdir, offset):
    blob = bytearray(_build_active_mime(SYNTHETIC_PAYLOAD))
    blob[offset:offset + 4] = struct.pack("<I", 0xFFFFFFFF)
    result, target_path = _parse_blob(tmpdir, bytes(blob))
    assert result is False
    assert not os.path.exists(target_path)

@pytest.mark.unit
def test_parse_active_mime_corrupt_compressed_tail(tmpdir):
    blob = bytearray(_build_active_mime(SYNTHETIC_PAYLOAD))
    assert blob[_COMPRESSED_OFFSET] == 0x78  # zlib header
    for i in range(_COMPRESSED_OFFSET, len(blob)):
        blob[i] ^= 0xFF
    result, target_path = _parse_blob(tmpdir, bytes(blob))
    assert result is False
    assert not os.path.exists(target_path)
