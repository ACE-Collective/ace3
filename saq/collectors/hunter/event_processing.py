#
# in hunt definitions you can use a special syntax to interpolate event data into the results
# the syntax is $TYPE{LOOKUP} where TYPE is the style of interpolation to use
# and LOOKUP is some kind of key to use to lookup the value in the event data
#
# TYPE is OPTIONAL and supports the following values:
# - key: the LOOKUP is used as a key to lookup the value in the event data
# - dot: the LOOKUP is treated as a dotted string path to access the field in the event data (using the glom library)
# 
# if not specified, the default for TYPE is "key"
#
# If LOOKUP needs to contain a literal { or } character, then it must be escaped using a backslash
#
# Examples:
#
# - ${field_name} -> equivalent to event[field_name]
# - $key{field_name} -> same as above
# - $dot{device.hostname} -> equivalent to event["device"]["hostname"]
# - $dot{device.hostname}@${file_path} -> equivalent to event["device"]["hostname"] + "@" + event["file_path"]
# - $key{device.hostname}@${file_path} -> equivalent to event["device.hostname"] + "@" + event["file_path"]
# 

import re
from typing import List

from glom import Path, PathAccessError, glom

# pattern to match $TYPE{LOOKUP} or ${LOOKUP}
_FIELD_PATTERN = re.compile(r"\$(?:([a-z]+))?\{((?:\\.|[^\\}])*)\}")

FIELD_LOOKUP_TYPE_KEY = "key"
FIELD_LOOKUP_TYPE_DOT = "dot"


def _unescape_lookup_value(field_path: str) -> str:
    """Converts escaped brace characters back to their literal form."""
    if "\\" not in field_path:
        return field_path

    return (
        field_path.replace("\\{", "{")
        .replace("\\}", "}")
    )

def _build_path_components(path: str) -> List[object] | None:
    """Converts the dotted string path into glom Path components."""
    components: List[object] = []
    for raw_part in path.split("."):
        part = raw_part.strip()
        if not part:
            return None

        try:
            index = int(part)
        except ValueError:
            components.append(part)
        else:
            components.append(index)

    return components


def extract_event_value(event: dict, lookup_type: str, field_path: str) -> tuple[bool, object]:
    """Extracts a value from the event data based on the lookup type and field path.

    Args:
        event: the event dictionary to extract from
        lookup_type: the type of lookup to perform (FIELD_LOOKUP_TYPE_KEY or FIELD_LOOKUP_TYPE_DOT)
        field_path: the path to the field to extract

    Returns:
        tuple of (success, value) where success is True if the value was found, False otherwise
    """
    if lookup_type == FIELD_LOOKUP_TYPE_KEY:
        # direct key lookup: event[field_path]
        # use a sentinel to distinguish between None value and missing key
        _MISSING = object()
        resolved_value = event.get(field_path, _MISSING)
        if resolved_value is _MISSING:
            return (False, None)
        return (True, resolved_value)
    else:  # lookup_type == FIELD_LOOKUP_TYPE_DOT
        # dotted path lookup using glom
        components = _build_path_components(field_path)
        if components is None:
            return (False, None)

        try:
            resolved_value = glom(event, Path(*components))
        except PathAccessError:
            return (False, None)

        return (True, resolved_value)


def interpolate_event_value(value: str, event: dict) -> str:
    """Interpolates event data into the given value."""
    if not isinstance(value, str):
        return value

    if not isinstance(event, dict):
        return value

    if not _FIELD_PATTERN.search(value):
        return value

    def replace(match: re.Match[str]) -> str:
        lookup_type = match.group(1)  # can be None, empty string, FIELD_LOOKUP_TYPE_KEY, or FIELD_LOOKUP_TYPE_DOT
        field_path = match.group(2).strip()

        if not field_path:
            return match.group(0)

        field_path = _unescape_lookup_value(field_path)

        # default to "key" if no type specified (None or empty string)
        if not lookup_type:
            lookup_type = FIELD_LOOKUP_TYPE_KEY

        # validate lookup type
        if lookup_type not in (FIELD_LOOKUP_TYPE_KEY, FIELD_LOOKUP_TYPE_DOT):
            return match.group(0)

        success, resolved_value = extract_event_value(event, lookup_type, field_path)

        if not success:
            return match.group(0)

        if resolved_value is None:
            return ""

        return str(resolved_value)

    return _FIELD_PATTERN.sub(replace, value)