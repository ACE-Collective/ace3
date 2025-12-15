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


def interpolate_event_value(value: str, event: dict) -> list[str]:
    """Interpolates event data into the given value.

    This supports fields that resolve to either scalar values or lists:
    - If a placeholder resolves to a scalar, it is interpolated normally.
    - If a placeholder resolves to a list, each element is interpolated separately.
    - If multiple placeholders resolve to lists, all combinations are returned.
    """
    assert isinstance(value, str)
    assert isinstance(event, dict)

    # if there are no interpolation patterns, then we just return the value as is
    if not _FIELD_PATTERN.search(value):
        return [value]

    # We build the output by treating the string as a sequence of segments.
    # Each segment is a list of possible strings:
    # - Literal text segments have a single option.
    # - Placeholder segments may have multiple options (if their value is a list).
    segments: list[list[str]] = []
    last_index = 0

    for match in _FIELD_PATTERN.finditer(value):
        # literal text before this match
        if match.start() > last_index:
            literal = value[last_index : match.start()]
            segments.append([literal])

        lookup_type = match.group(1)  # can be None, empty string, FIELD_LOOKUP_TYPE_KEY, or FIELD_LOOKUP_TYPE_DOT
        field_path = match.group(2).strip()

        # default behavior if something goes wrong with this placeholder:
        # keep the original text for this match
        default_segment = [match.group(0)]

        if not field_path:
            # empty lookup, leave placeholder as-is
            segments.append(default_segment)
            last_index = match.end()
            continue

        field_path = _unescape_lookup_value(field_path)

        # default to "key" if no type specified (None or empty string)
        if not lookup_type:
            lookup_type = FIELD_LOOKUP_TYPE_KEY

        # validate lookup type
        if lookup_type not in (FIELD_LOOKUP_TYPE_KEY, FIELD_LOOKUP_TYPE_DOT):
            segments.append(default_segment)
            last_index = match.end()
            continue

        success, resolved_value = extract_event_value(event, lookup_type, field_path)

        if not success:
            segments.append(default_segment)
            last_index = match.end()
            continue

        # Build the list of replacement options for this placeholder.
        if resolved_value is None:
            # Preserve previous behavior: None becomes empty string.
            segment_values = [""]

        elif isinstance(resolved_value, list):
            # Each element of the list becomes a separate interpolation.
            # Convert elements to strings, treating None as empty string.
            if not resolved_value:
                # An empty list yields no options; this effectively results in no
                # combinations that include this placeholder.
                segment_values = []
            else:
                segment_values = [
                    "" if item is None else str(item) for item in resolved_value
                ]

        else:
            segment_values = [str(resolved_value)]

        # If there are no options (empty list), then there are no valid
        # combinations that include this placeholder.
        if not segment_values:
            return []

        segments.append(segment_values)
        last_index = match.end()

    # trailing literal text after the last match
    if last_index < len(value):
        segments.append([value[last_index:]])

    # Now compute the cartesian product across all segments to generate all
    # interpolated strings.
    results: list[str] = [""]
    for segment_options in segments:
        new_results: list[str] = []
        for base in results:
            for option in segment_options:
                new_results.append(base + option)

        results = new_results

    return results