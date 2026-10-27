import shutil
import subprocess

import pytest

from saq.util.ui import hexdump, hexdump_line_html, hexdump_lines


def _real_hexdump(content: bytes) -> str:
    return subprocess.run(["hexdump", "-C"], input=content, capture_output=True, check=True).stdout.decode()


@pytest.mark.unit
@pytest.mark.skipif(shutil.which("hexdump") is None, reason="needs hexdump to compare with")
@pytest.mark.parametrize("content", [
    b"",
    b"A",
    b"0123456789abcdef",
    b"0123456789abcdef0",
    b"\xff" * 48,
    b"\xff" * 48 + b"tail",
    b"x" * 16 + b"y" * 16 + b"x" * 16,
    b"\x00" * 15,
    b"a\\nb\\\\c",
    bytes(range(256)) * 3,
])
def test_hexdump_is_hexdump_c(content):
    assert hexdump(content) == _real_hexdump(content)


@pytest.mark.unit
def test_hexdump_lines_takes_chunks():
    assert list(hexdump_lines(iter([b"0123456789abcdef", b"0123456789abcdef", b"!"]))) == [
        "00000000  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  |0123456789abcdef|\n",
        "*\n",
        "00000020  21                                                |!|\n",
        "00000021\n",
    ]


@pytest.mark.unit
@pytest.mark.parametrize("chunk", [b"Hello, world!\n", bytes(range(16)), b"0123456789"])
def test_hexdump_line_html_unmarked_is_the_plain_line(chunk):
    assert hexdump_line_html(32, chunk, range(0)) == hexdump(b"\x00" * 32 + chunk).splitlines()[2]


@pytest.mark.unit
def test_hexdump_line_html_marks_a_range():
    line = hexdump_line_html(16, b"ab<cdefghijklmno", range(18, 26))
    assert line == ("00000010  61 62 <mark>3c 63 64 65 66 67  68 69</mark> 6a 6b 6c 6d 6e 6f  "
                    "|ab<mark>&lt;cdefghi</mark>jklmno|")
