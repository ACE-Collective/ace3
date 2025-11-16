import base64
import logging



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

