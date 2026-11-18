import distorm3
import pytest

from saq.modules.file_analysis.disassembly import disassemble


@pytest.mark.unit
def test_disassembly_aligns_on_the_match_past_the_start_of_the_file():
    # each 0xb8 starts a 5 byte MOV EAX, imm32, so decoding from the start of the context runs
    # through the match; only a start 4 bytes in lands an instruction on it
    context = b"\xb8" * 64 + b"\x31\xc0" + b"\x90" * 64
    listing = disassemble("sample.bin", 1000, 64, 2, context, distorm3.Decode32Bits)
    assert "<b>0x00000428     31c0                XOR EAX, EAX</b>" in listing
