import base64
import logging
from html import escape

def format_item_list_for_summary(item_list: list[str], max_items: int = 20) -> str:
    """Returns a string of the first max_items items in the list, separated by commas.
    If more than max_items, returns the first max_items and number of remaining items."""
    result = ", ".join(item_list[:max_items])
    if len(item_list) > max_items:
        result += f" + {len(item_list) - max_items} more"

    return result

def decode_base64(value: str) -> bytes:
    """Decode a base64 string, adding missing padding if necessary."""
    if not isinstance(value, str):
        raise TypeError("value must be a string")

    trimmed = value.strip()
    missing_padding = len(trimmed) % 4
    if missing_padding:
        trimmed += "=" * (4 - missing_padding)

    return base64.urlsafe_b64decode(trimmed)

def decode_ascii_hex(value: str) -> bytes:
    """Decode an ASCII hex string to bytes, dropping trailing odd characters."""
    if not isinstance(value, str):
        raise TypeError("value must be a string")

    trimmed = value.strip()
    if len(trimmed) % 2:
        logging.warning("decode_ascii_hex: dropping trailing character from odd-length input")
        trimmed = trimmed[:-1]

    if not trimmed:
        return b""

    return bytes.fromhex(trimmed)

def is_base64(value: str) -> bool:
    """Returns True if the given string is a valid base64 encoded string."""
    if not isinstance(value, str):
        return False

    trimmed = value.strip()
    if not trimmed:
        return False

    # Base64 strings should only contain valid base64 characters
    # Standard base64: A-Z, a-z, 0-9, +, /, and = for padding
    # URL-safe base64: A-Z, a-z, 0-9, -, _, and = for padding
    # We'll check for both variants
    base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")
    if not all(c in base64_chars for c in trimmed):
        return False

    # Try to decode it to verify it's actually valid base64
    try:
        # Add missing padding if necessary (like decode_base64 does)
        missing_padding = len(trimmed) % 4
        if missing_padding:
            test_value = trimmed + "=" * (4 - missing_padding)
        else:
            test_value = trimmed

        # Try URL-safe first (more common), then standard
        try:
            base64.urlsafe_b64decode(test_value)
        except Exception:
            base64.b64decode(test_value)

        return True

    except Exception:
        return False



def hexdump_line(offset: int, chunk: bytes, marked: range = range(0), html: bool = False) -> str:
    """One line of `hexdump -C` for up to 16 bytes at offset. With html, the text is escaped and
    the bytes whose offsets are in marked are wrapped in <mark> in both columns."""
    hex_cells, text_cells = [], []
    for index in range(16):
        separator = "  " if index == 8 else (" " if index else "")
        if index >= len(chunk):
            hex_cells.append((separator + "  ", False))
            continue

        is_marked = html and offset + index in marked
        hex_cells.append((separator, is_marked and offset + index - 1 in marked))
        hex_cells.append((f"{chunk[index]:02x}", is_marked))
        text_cells.append((chr(chunk[index]) if 0x20 <= chunk[index] < 0x7f else ".", is_marked))

    def render(cells: list[tuple[str, bool]]) -> str:
        if not html:
            return "".join(text for text, _ in cells)

        result = []
        for text, is_marked in cells:
            text = escape(text)
            result.append(f"<mark>{text}</mark>" if is_marked else text)

        # a run of marked cells is one mark
        return "".join(result).replace("</mark><mark>", "")

    return f"{offset:08x}  {render(hex_cells)}  |{render(text_cells)}|"
