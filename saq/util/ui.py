from collections.abc import Iterable, Iterator
from html import escape

from saq.configuration.config import get_config


def human_readable_size(size):
    from math import log2

    _suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB']

    # determine binary order in steps of size 10 
    # (coerce to int, // still returns a float)
    order = int(log2(size) / 10) if size else 0
    # format file size
    # (.4g results in rounded numbers for exact matches and max 3 decimals, 
    # should never resort to exponent values)
    return '{:.4g} {}'.format(size / (1 << (order * 10)), _suffixes[order])

def create_histogram_string(data):
    """A convenience function that creates a graph in the form of a string.

    :param dict data: A dictionary, where the values are integers representing a count of the keys.
    :return: A graph in string form, pre-formatted for raw printing.
    """
    assert isinstance(data, dict)
    for key in data.keys():
        assert isinstance(data[key], int)
    total_results = sum([value for value in data.values()])
    txt = ""
    # order keys for printing in order (purly ascetics)
    ordered_keys = sorted(data, key=lambda k: data[k])
    results = []
    # longest_key used to calculate how many white spaces should be printed
    # to make the graph columns line up with each other
    longest_key = 0
    for key in ordered_keys:
        value = data[key]
        longest_key = len(key) if len(key) > longest_key else longest_key
        # IMPOSING LIMITATION: truncating keys to 95 chars, keeping longest key 5 chars longer
        longest_key = 100 if longest_key > 100 else longest_key
        percent = value / total_results * 100
        results.append((key[:95], value, percent, u"\u25A0" * (int(percent / 2))))
    # two for loops are ugly, but allowed us to count the longest_key -
    # so we loop through again to print the text
    for r in results:
        txt += "%s%s: %5s - %5s%% %s\n" % (int(longest_key - len(r[0])) * ' ', r[0], r[1],
                                           str(r[2])[:4], u"\u25A0" * (int(r[2] / 2)))
    return txt

def get_tag_css_class(tag: str) -> str:
    """Returns the CSS class to use for the given tag."""
    # first get the level assigned to the tag
    level = get_tag_level(tag)

    try:
        return get_config().tag_css_class.get(level, 'label-default')
    except Exception:
        return 'label-default'

def get_tag_level(tag_name: str) -> str:
    """Get the tag level from a tag name string."""
    from saq.constants import TAG_LEVEL_INFO
    # note that a tag can have the form of tag_name:random_stuff
    if ':' in tag_name:
        tag_name = tag_name.split(':', 1)[0]
    
    # does this tag exist in the configuration file?
    level = get_config().tags.get(tag_name)
    if not level:
        level = TAG_LEVEL_INFO
    
    return level

def get_tag_score(tag_name: str) -> int:
    """Get the tag score from a tag name string."""
    from saq.constants import TAG_LEVEL_FALSE_POSITIVE, TAG_LEVEL_INFO, TAG_LEVEL_WARNING, TAG_LEVEL_ALERT, TAG_LEVEL_CRITICAL
    
    level = get_tag_level(tag_name)
    
    if level == TAG_LEVEL_FALSE_POSITIVE:
        return 0
    elif level == TAG_LEVEL_INFO:
        return 0
    elif level == TAG_LEVEL_WARNING:
        return 1
    elif level == TAG_LEVEL_ALERT:
        return 3
    elif level == TAG_LEVEL_CRITICAL:
        return 10
    else:
        return 0


def _hexdump_line(offset: int, chunk: bytes) -> str:
    hex_bytes = [f"{byte:02x} " for byte in chunk]
    hex_area = "".join(hex_bytes[:8]) + " " + "".join(hex_bytes[8:])
    printable = "".join(chr(byte) if 0x20 <= byte < 0x7f else "." for byte in chunk)
    return f"{offset:08x}  {hex_area:<49} |{printable}|\n"


def hexdump_line_html(offset: int, chunk: bytes, marked: range) -> str:
    """_hexdump_line as HTML: the text is escaped and the bytes whose offsets are in marked are
    wrapped in <mark>, in both the hex and the text columns."""
    hex_cells, text_cells = [], []
    for index in range(16):
        separator = "  " if index == 8 else (" " if index else "")
        if index >= len(chunk):
            hex_cells.append((separator + "  ", False))
            continue

        is_marked = offset + index in marked
        hex_cells.append((separator, is_marked and offset + index - 1 in marked))
        hex_cells.append((f"{chunk[index]:02x}", is_marked))
        text_cells.append((chr(chunk[index]) if 0x20 <= chunk[index] < 0x7f else ".", is_marked))

    def render(cells: list[tuple[str, bool]]) -> str:
        result = []
        for text, is_marked in cells:
            text = escape(text)
            result.append(f"<mark>{text}</mark>" if is_marked else text)

        # a run of marked cells is one mark
        return "".join(result).replace("</mark><mark>", "")

    return f"{offset:08x}  {render(hex_cells)}  |{render(text_cells)}|"


def hexdump_lines(chunks: Iterable[bytes]) -> Iterator[str]:
    """The lines `hexdump -C` prints for data given as 16 byte chunks (the last one may be shorter):
    16 bytes a line as the offset, the bytes in hex and the printable ones as text, a run of lines
    repeating the one before it as a single "*", and the length last."""
    offset = 0
    previous = None
    squeezing = False
    for chunk in chunks:
        if chunk == previous:
            if not squeezing:
                yield "*\n"
                squeezing = True
        else:
            yield _hexdump_line(offset, chunk)
            squeezing = False
        previous = chunk
        offset += len(chunk)

    if offset:
        yield f"{offset:08x}\n"


def hexdump(data: bytes) -> str:
    """data as `hexdump -C` prints it."""
    return "".join(hexdump_lines(data[i:i + 16] for i in range(0, len(data), 16)))
