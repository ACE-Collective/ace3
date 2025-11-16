from enum import Enum

from saq.util.strings import decode_ascii_hex, decode_base64

class DecoderType(Enum):
    BASE64 = "base64"
    ASCII_HEX = "ascii_hex"

def decode_value(value: str, decoder: DecoderType) -> bytes:
    if decoder == DecoderType.BASE64:
        return decode_base64(value)
    elif decoder == DecoderType.ASCII_HEX:
        return decode_ascii_hex(value)
    else:
        raise ValueError(f"Invalid decoder: {decoder}")
