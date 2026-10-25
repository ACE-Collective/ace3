import shutil
import subprocess

import pytest

from saq.util.ui import hexdump, hexdump_lines


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
