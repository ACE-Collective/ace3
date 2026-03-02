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

# https://www.geeksforgeeks.org/python-add-logging-to-python-libraries/
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

def parse_mime(file_path: str, output_dir: str) -> list[str]:
    """Parses a file for (a single) embedded MIME file.
    Any embedded files are stored in the directory specified by output_dir.
    If the directory does not exist it is created.
    Each extracted file is named extracted-N where N is the 0-based index into the MIME document.

    The list of paths to all extracted files is returned."""

    logger.debug(f"analyzing {file_path} for hidden mime data")
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
            logger.info(f"parsing {file_path} MIME from position {m.span()[0]} to {m_last.span()[1]}")
            target_memory = mm[m.span()[0]:m_last.span()[1]]
        else:
            # default to the rest of the file if you can't find it
            logger.info(f"parsing {file_path} MIME from position {m.span()[0]} to end of file (no end boundary detected)")
            target_memory = mm[m.span()[0]:]

        # need somewhere to put the extracted files
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)

        parser = BytesParser()
        parsed_mime = parser.parsebytes(target_memory)
        index = 0
        extracted_files = []
        for part in parsed_mime.walk():
            logger.info(f"mime part {index} content type {part.get_content_type()}")
            target_path = os.path.join(output_dir, f"extracted-{index}")
            payload = part.get_payload(decode=True)
            if payload:
                with open(target_path, "wb") as fp_out:
                    fp_out.write(part.get_payload(decode=True))
                extracted_files.append(target_path)
                index += 1

        return extracted_files

def parse_active_mime(file_path: str, target_path: str) -> bool:
    """Parses the given ActiveMIME document and stores the extracted data in the file specified by target_path."""
    with open(file_path, "rb") as fp:
        rawdoc = fp.read()

    header = rawdoc[0:12]
    if not header.startswith(b'ActiveMime'):
        logger.debug(f"{file_path} does not start with ActiveMime")
        return False

    # Should be 01f0
    unknown_a =  rawdoc[12:14]

    field_size = unpack('<I', rawdoc[14:18])[0]
    cursor = 18

    # Should be ffffffff
    unknown_b = rawdoc[cursor:cursor+field_size]
    cursor += field_size

    # Should be {x}0000{y}f0
    unknown_c = rawdoc[cursor:cursor+4]
    cursor += 4

    compressed_size = unpack('<I', rawdoc[cursor:cursor + 4])[0]
    cursor += 4

    field_size_d = unpack('<I', rawdoc[cursor:cursor+4])[0]
    cursor += 4

    field_size_e = unpack('<I', rawdoc[cursor:cursor+4])[0]
    cursor += 4

    # Should be 00000000 or 00000000 00000001
    unknown_d = rawdoc[cursor:cursor + field_size_d]
    cursor += field_size_d

    vba_tail_type = unpack('<I', rawdoc[cursor:cursor + field_size_e])[0]
    cursor += field_size_e

    if vba_tail_type == 0:
        has_vba_tail = True

    size = unpack('<I', rawdoc[cursor:cursor + 4])[0]
    cursor += 4

    compressed_data = rawdoc[cursor:]
    data = zlib.decompress(compressed_data)

    #if data[0:4].hex() == b'd0cf11e0':
        #is_ole_doc = True

    logger.info(f"writing extracted ActiveMime from {file_path} to {target_path}")
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
