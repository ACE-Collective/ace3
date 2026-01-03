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
