#!/usr/bin/env python3

import logging
import os
import os.path
import re
import zlib

from argparse import ArgumentParser
from email.parser import BytesParser
from mmap import mmap
from struct import unpack

# cONtENT-Type:                 multipart/related; boundary="----=_NextPart_01D9BFB6.09C21E10"
RE_BOUNDARY = re.compile(rb'content-type\s*:.*?boundary\s*?=(\S+)', re.I)

def parse_mime(file_path: str, output_dir: str) -> list[str]:
    """Parses a file for (a single) embedded MIME file.
    Any embedded files are stored in the directory specified by output_dir.
    If the directory does not exist it is created.
    Each extracted file is named extracted-N where N is the 0-based index into the MIME document.

    The list of paths to all extracted files is returned."""

    logging.debug(f"analyzing {file_path} for hidden mime data")
    with open(file_path, "r+b") as fp:
        mm = mmap(fp.fileno(), 0)

        # look for something that looks like it might be a MIME boundary
        m = RE_BOUNDARY.search(mm)
        if not m:
            return []

        boundary = m.group(1)
        # guess the boundary can optionally be in quotes?
        if boundary.startswith(b'"') and boundary.endswith(b'"'):
            boundary = boundary[1:-1]

        # look for the ending boundary marker
        # trying to figure out if the MIME data extends to the end of the file or not
        # re.escape the boundary since it may contain regex metacharacters (e.g. when
        # matched from HTML/JS that resembles Content-Type, like SocialCalc code)
        RE_END_BOUNDARY = re.compile(b'--' + re.escape(boundary) + b'--')
        m_last = RE_END_BOUNDARY.search(mm)
        if m_last:
            logging.debug(f"parsing {file_path} MIME from position {m.span()[0]} to {m_last.span()[1]}")
            target_memory = mm[m.span()[0]:m_last.span()[1]]
        else:
            # default to the rest of the file if you can't find it
            logging.debug(f"parsing {file_path} MIME from position {m.span()[0]} to end of file (no end boundary detected)")
            target_memory = mm[m.span()[0]:]

        # need somewhere to put the extracted files
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)

        parser = BytesParser()
        parsed_mime = parser.parsebytes(target_memory)
        index = 0
        extracted_files = []
        for part in parsed_mime.walk():
            logging.debug(f"mime part {index} content type {part.get_content_type()}")
            target_path = os.path.join(output_dir, f"extracted-{index}")
            payload = part.get_payload(decode=True)
            if payload:
                with open(target_path, "wb") as fp_out:
                    fp_out.write(part.get_payload(decode=True))
                extracted_files.append(target_path)
                index += 1

        return extracted_files

class _MalformedActiveMime(Exception):
    """Raised when an ActiveMime document is truncated or its fields are inconsistent."""
    def __init__(self, offset: int, reason: str):
        super().__init__(f"{reason} at offset {offset}")
        self.offset = offset
        self.reason = reason

def _read_uint32(rawdoc: bytes, cursor: int) -> int:
    """Returns the little-endian uint32 at cursor, raising _MalformedActiveMime if the buffer is too short."""
    if cursor + 4 > len(rawdoc):
        raise _MalformedActiveMime(cursor, f"truncated reading uint32 (buffer size {len(rawdoc)})")

    return unpack('<I', rawdoc[cursor:cursor + 4])[0]

def _skip(rawdoc: bytes, cursor: int, length: int) -> int:
    """Returns cursor advanced by length, raising _MalformedActiveMime if that runs past the end of the buffer."""
    if cursor + length > len(rawdoc):
        raise _MalformedActiveMime(cursor, f"field of size {length} exceeds buffer size {len(rawdoc)}")

    return cursor + length

def parse_active_mime(file_path: str, target_path: str) -> bool:
    """Parses the given ActiveMIME document and stores the extracted data in the file specified by target_path."""
    with open(file_path, "rb") as fp:
        rawdoc = fp.read()

    header = rawdoc[0:12]
    if not header.startswith(b'ActiveMime'):
        logging.debug(f"{file_path} does not start with ActiveMime")
        return False

    try:
        # Should be 01f0
        cursor = _skip(rawdoc, 12, 2)

        field_size = _read_uint32(rawdoc, cursor)
        cursor += 4

        # Should be ffffffff
        cursor = _skip(rawdoc, cursor, field_size)

        # Should be {x}0000{y}f0
        cursor = _skip(rawdoc, cursor, 4)

        compressed_size = _read_uint32(rawdoc, cursor)
        cursor += 4

        field_size_d = _read_uint32(rawdoc, cursor)
        cursor += 4

        field_size_e = _read_uint32(rawdoc, cursor)
        cursor += 4

        # Should be 00000000 or 00000000 00000001
        cursor = _skip(rawdoc, cursor, field_size_d)

        # the vba tail type is read as a uint32, so its field must be exactly 4 bytes
        if field_size_e != 4:
            raise _MalformedActiveMime(cursor, f"unexpected vba tail type field size {field_size_e}")

        vba_tail_type = _read_uint32(rawdoc, cursor)
        cursor += field_size_e

        size = _read_uint32(rawdoc, cursor)
        cursor += 4

        compressed_data = rawdoc[cursor:]
        try:
            data = zlib.decompress(compressed_data)
        except zlib.error as e:
            raise _MalformedActiveMime(cursor, f"unable to decompress: {e}")

    except _MalformedActiveMime as e:
        logging.info(f"{file_path} is a malformed ActiveMime document at offset {e.offset}: {e.reason}")
        return False

    #if data[0:4].hex() == b'd0cf11e0':
        #is_ole_doc = True

    logging.debug(f"writing extracted ActiveMime from {file_path} to {target_path}")
    with open(target_path, "wb") as fp:
        fp.write(data)

    return True

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("file", help="The file to parse.")
    parser.add_argument("output_dir", help="The directory to place the extracted files into.")
    args = parser.parse_args()

    parse_mime(args.file, args.output_dir)
    #parse_active_mime(args.file, args.target)
