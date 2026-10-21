#!/usr/bin/env python3
"""Copies a pcapng without what it records about the machine that captured it: the hardware, OS and
comment options of the section header, the name, description, OS and filter options of each interface,
and the interface statistics blocks. Packets, timestamp resolution, the writing application and
decryption secrets blocks are kept. Run by generate_fixtures.sh.

usage: strip_pcapng_metadata.py <in.pcapng> <out.pcapng>"""

import struct
import sys

SECTION_HEADER = 0x0A0D0D0A
INTERFACE_DESCRIPTION = 0x00000001
INTERFACE_STATISTICS = 0x00000005

OPT_COMMENT = 1
# section header: shb_hardware, shb_os (shb_userappl, 4, is kept)
DROP_SECTION_OPTIONS = {OPT_COMMENT, 2, 3}
# interface: if_name, if_description, if_filter, if_os, if_hardware
DROP_INTERFACE_OPTIONS = {OPT_COMMENT, 2, 3, 11, 12, 15}


def _strip_options(data: bytes, endian: str, drop: set[int]) -> bytes:
    kept = b""
    offset = 0
    while offset + 4 <= len(data):
        code, length = struct.unpack_from(endian + "HH", data, offset)
        if code == 0:
            break
        padded = length + (-length % 4)
        if code not in drop:
            kept += data[offset:offset + 4 + padded]
        offset += 4 + padded
    return kept + struct.pack(endian + "HH", 0, 0)


def _block(endian: str, block_type: int, body: bytes) -> bytes:
    length = 12 + len(body)
    return struct.pack(endian + "II", block_type, length) + body + struct.pack(endian + "I", length)


def strip(data: bytes) -> bytes:
    out = b""
    offset = 0
    endian = "<"
    while offset + 12 <= len(data):
        if data[offset:offset + 4] == b"\x0a\x0d\x0d\x0a":
            endian = "<" if data[offset + 8:offset + 12] == b"\x4d\x3c\x2b\x1a" else ">"
        block_type, length = struct.unpack_from(endian + "II", data, offset)
        body = data[offset + 8:offset + length - 4]
        if block_type == SECTION_HEADER:
            # the section length (an int64 after magic and version) is unknown once the section shrinks
            magic_version = body[:8]
            out += _block(endian, block_type, magic_version + struct.pack(endian + "q", -1)
                          + _strip_options(body[16:], endian, DROP_SECTION_OPTIONS))
        elif block_type == INTERFACE_DESCRIPTION:
            out += _block(endian, block_type, body[:8] + _strip_options(body[8:], endian, DROP_INTERFACE_OPTIONS))
        elif block_type != INTERFACE_STATISTICS:
            out += data[offset:offset + length]
        offset += length
    return out


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as fp:
        stripped = strip(fp.read())
    with open(sys.argv[2], "wb") as fp:
        fp.write(stripped)
