# vim: sw=4:ts=4:et:cc=120

import datetime
import logging
import re
from dataclasses import dataclass
from typing import Callable, Optional

from jinja2 import UndefinedError
from pydantic import BaseModel, Field

from saq.analysis.observable import Observable
from saq.constants import F_FILE, SUMMARY_DETAIL_FORMAT_JINJA
from saq.observables.generator import create_observable
from saq.observables.mapping import (
    ObservableMapping,
    RelationshipMapping,
    apply_mapping_properties,
)
from saq.query.config import SummaryDetailConfig
from saq.query.decoder import decode_value
from saq.query.event_processing import (
    contains_unresolved_placeholders,
    extract_event_value,
    interpolate_event_value,
    parse_field_reference,
    strip_unresolved_placeholders,
)
from saq.query.summary_detail_rendering import render_jinja_template


class FileContent(BaseModel):
    file_name: str = Field(..., description="The name of the file as defined by the observable mapping.")
    content: bytes = Field(..., description="The content of the file.")
    directives: list[str] = Field(default_factory=list, description="The directives to add to the file observable.")
    tags: list[str] = Field(default_factory=list, description="The tags to add to the file observable.")
    volatile: bool = Field(default=False, description="Whether to add the observable as volatile.")
    display_type: Optional[str] = Field(default=None, description="The display type to use for the file observable.")
    display_value: Optional[str] = Field(default=None, description="The display value to use for the file observable.")


def interpret_event_value(observable_mapping: ObservableMapping, event: dict, field_override: str = None) -> list[str]:
    """Interprets the event value(s) for the given event and observable mapping.

    Returns a list of observed, interpolated values.

    Args:
        observable_mapping: The observable mapping configuration.
        event: The event dict to extract values from.
        field_override: If provided, use this field name instead of fields[0] for non-interpolated values.
    """
    assert isinstance(observable_mapping, ObservableMapping)
    assert isinstance(event, dict)

    result: list[str] = []

    if not observable_mapping.fields:
        raise ValueError(f"no fields specified for observable mapping {observable_mapping}")

    # is the value for this mapping not computed?
    if observable_mapping.value is None:
        # then we just take the value
        field_name = field_override if field_override is not None else observable_mapping.fields[0]
        observed_value = event[field_name]
    else:
        # otherwise we interpolate the value from the event
        observed_value = interpolate_event_value(observable_mapping.value, event)

    # we always return a list of values, even if there is only one
    if not isinstance(observed_value, list):
        result = [observed_value]
    else:
        result = observed_value

    # if any of the results are bytes, convert them into strings using utf-8
    return [_.decode("utf-8", errors="ignore") if isinstance(_, bytes) else str(_) for _ in result]


@dataclass
class ExtractedObservable:
    observable: Observable
    mapping: ObservableMapping
    matched_field: str


def extract_observables_from_event(
    event: dict,
    mappings: list[ObservableMapping],
    event_time: Optional[datetime.datetime] = None,
    global_ignored_patterns: list[re.Pattern] = None,
    value_filter: Optional[Callable] = None,
) -> tuple[list[ExtractedObservable], list[FileContent], dict[Observable, list[RelationshipMapping]]]:
    """Extract observables from a single event/result based on observable mappings.

    This is the core unified extraction pipeline used by both hunts and API analysis modules.

    Args:
        event: The event/result dict to extract from.
        mappings: The observable mapping configurations.
        event_time: Optional event timestamp for temporal observables.
        global_ignored_patterns: Optional config-level ignored value patterns.
        value_filter: Optional callback(field_name, obs_type, value) -> filtered_value
                      for pre-creation value transformation. Default: identity.

    Returns:
        (extracted_observables, file_contents, relationship_tracking) tuple.
    """
    extracted: list[ExtractedObservable] = []
    file_contents: list[FileContent] = []
    relationship_tracking: dict[Observable, list[RelationshipMapping]] = {}

    for mapping in mappings:
        from glom import PathAccessError

        def _is_field_present(field_name, _event=event, _mapping=mapping):
            try:
                success, _ = extract_event_value(_event, _mapping.field_lookup_type, field_name)
                return success
            except PathAccessError:
                return False

        for field_group in mapping.resolve_fields(_is_field_present):
            # ANY mode: field_group is a single field, use as field_override
            # ALL mode: field_group is all fields, no override needed (value template uses all)
            field_override = field_group[0] if len(field_group) == 1 else None
            matched_field = field_group[0]

            _process_mapping_values(
                mapping, event, event_time, matched_field,
                extracted, file_contents, relationship_tracking,
                global_ignored_patterns=global_ignored_patterns,
                value_filter=value_filter,
                field_override=field_override,
            )

    return extracted, file_contents, relationship_tracking


def _process_mapping_values(
    mapping: ObservableMapping,
    event: dict,
    event_time: Optional[datetime.datetime],
    matched_field: str,
    extracted: list[ExtractedObservable],
    file_contents: list[FileContent],
    relationship_tracking: dict[Observable, list[RelationshipMapping]],
    global_ignored_patterns: list[re.Pattern] = None,
    value_filter: Optional[Callable] = None,
    field_override: str = None,
):
    """Process a single observable mapping for an event, creating observables or file contents."""
    decoded_observed_value: Optional[bytes] = None

    for observed_value in interpret_event_value(mapping, event, field_override=field_override):
        if not observed_value:
            continue

        if global_ignored_patterns:
            from saq.observables.mapping import is_ignored_value
            if is_ignored_value(global_ignored_patterns, observed_value):
                continue

        if mapping.ignored_values and mapping.is_ignored_value(observed_value):
            continue

        if mapping.type == F_FILE:
            if mapping.file_decoder is not None:
                decoded_observed_value = decode_value(observed_value, mapping.file_decoder)

            if decoded_observed_value is None:
                decoded_observed_value = observed_value.encode('utf-8')

            for target_file_name in interpolate_event_value(mapping.file_name, event):
                interpolated_directives = []
                for directive in mapping.directives:
                    interpolated_directives.extend(interpolate_event_value(directive, event))

                interpolated_tags = []
                for tag in mapping.tags:
                    interpolated_tags.extend(interpolate_event_value(tag, event))

                file_contents.append(FileContent(
                    file_name=target_file_name,
                    content=decoded_observed_value,
                    directives=interpolated_directives,
                    tags=interpolated_tags,
                    volatile=mapping.volatile,
                    display_type=mapping.display_type,
                    display_value=mapping.display_value
                ))

            continue

        # Apply value_filter if provided (for API analysis filter_observable_value hook)
        final_value = observed_value
        if value_filter is not None:
            final_value = value_filter(matched_field, mapping.type, observed_value)

        observable = create_observable(mapping.type, final_value, volatile=mapping.volatile)

        if observable is None:
            logging.warning(
                f"unable to create observable {mapping.type} with value {final_value}"
            )
            continue

        if mapping.time and event_time is not None:
            observable.time = event_time

        apply_mapping_properties(observable, mapping,
                                 interpolate_fn=interpolate_event_value, event=event)

        if mapping.relationships:
            relationship_tracking[observable] = mapping.relationships

        extracted.append(ExtractedObservable(
            observable=observable,
            mapping=mapping,
            matched_field=matched_field,
        ))


def event_has_required_fields(event: dict, required_fields: list[str]) -> bool:
    """Check if the event has all required fields present."""
    for field_spec in required_fields:
        lookup_type, field_path = parse_field_reference(field_spec)
        success, _ = extract_event_value(event, lookup_type, field_path)
        if not success:
            return False
    return True


def compute_dedup_key(event: dict, dedup_fields: list[str]) -> tuple:
    """Build a dedup key tuple from the event values for each dedup field."""
    parts = []
    for field_spec in dedup_fields:
        lookup_type, field_path = parse_field_reference(field_spec)
        success, value = extract_event_value(event, lookup_type, field_path)
        if success:
            # convert lists/dicts to a hashable representation
            if isinstance(value, list):
                value = tuple(value)
            elif isinstance(value, dict):
                value = tuple(sorted(value.items()))
            parts.append(value)
        else:
            parts.append(None)
    return tuple(parts)


def render_sd_content(sd_config: SummaryDetailConfig, event: dict) -> Optional[str]:
    """Render summary detail content for a single event. Returns None to skip."""
    strict = sd_config.required_fields is None
    if sd_config.format == SUMMARY_DETAIL_FORMAT_JINJA:
        try:
            return render_jinja_template(sd_config.content, event, strict=strict)
        except UndefinedError:
            return None
    else:
        content_values = interpolate_event_value(sd_config.content, event)
        if not content_values:
            return None
        content = content_values[0]
        if sd_config.required_fields is not None:
            # partial resolution: strip unresolved placeholders instead of skipping
            content = strip_unresolved_placeholders(content)
        else:
            if contains_unresolved_placeholders(content):
                return None
        return content


def render_sd_header(sd_config: SummaryDetailConfig, event: dict) -> tuple[bool, Optional[str]]:
    """Render summary detail header for a single event.

    Returns (success, header). success=False means skip the event.
    """
    if sd_config.header is None:
        return (True, None)

    strict = sd_config.required_fields is None
    if sd_config.format == SUMMARY_DETAIL_FORMAT_JINJA:
        try:
            rendered = render_jinja_template(sd_config.header, event, strict=strict)
        except UndefinedError:
            return (False, None)
        if rendered is None:
            return (False, None)
        return (True, rendered)
    else:
        header_values = interpolate_event_value(sd_config.header, event)
        if not header_values:
            return (False, None)
        header = header_values[0]
        if sd_config.required_fields is not None:
            header = strip_unresolved_placeholders(header)
        else:
            if contains_unresolved_placeholders(header):
                return (False, None)
        return (True, header)


def process_summary_details(
    summary_details: list[SummaryDetailConfig],
    query_results: list[dict],
    add_detail_fn: Callable[[str, Optional[str], str], None],
):
    """Process summary detail definitions against query results.

    For each summary detail config, interpolates content and optional header against
    each event and calls add_detail_fn with the results. Respects the limit setting.

    Args:
        summary_details: The summary detail configurations.
        query_results: The list of event/result dicts.
        add_detail_fn: Callback(content, header, format) to add a summary detail.
    """
    for sd_config in summary_details:
        if sd_config.grouped:
            process_grouped_summary_detail(sd_config, query_results, add_detail_fn)
        else:
            process_ungrouped_summary_detail(sd_config, query_results, add_detail_fn)


def process_ungrouped_summary_detail(
    sd_config: SummaryDetailConfig,
    query_results: list[dict],
    add_detail_fn: Callable[[str, Optional[str], str], None],
):
    """Process a single ungrouped summary detail config — one detail per event."""
    count = 0
    seen_keys: set[tuple] = set()

    for event in query_results:
        # required fields check
        if sd_config.required_fields is not None:
            if not event_has_required_fields(event, sd_config.required_fields):
                continue

        # dedup check
        if sd_config.dedup_fields is not None:
            dedup_key = compute_dedup_key(event, sd_config.dedup_fields)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

        content = render_sd_content(sd_config, event)
        if content is None:
            continue

        header_ok, header = render_sd_header(sd_config, event)
        if not header_ok:
            continue

        if count >= sd_config.limit:
            if count == sd_config.limit:
                logging.warning(
                    "summary detail limit (%s) reached for definition content=%s",
                    sd_config.limit, sd_config.content,
                )
            count += 1
            continue

        add_detail_fn(content, header, sd_config.format)
        count += 1


def collect_qualifying_events(
    sd_config: SummaryDetailConfig,
    query_results: list[dict],
) -> list[dict]:
    """Filter events through required_fields, dedup, and limit for grouped Jinja rendering."""
    events = []
    seen_keys: set[tuple] = set()
    limit_warned = False
    for event in query_results:
        if sd_config.required_fields is not None:
            if not event_has_required_fields(event, sd_config.required_fields):
                continue
        if sd_config.dedup_fields is not None:
            dedup_key = compute_dedup_key(event, sd_config.dedup_fields)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
        if len(events) >= sd_config.limit:
            if not limit_warned:
                logging.warning(
                    "summary detail limit (%s) reached for definition content=%s",
                    sd_config.limit, sd_config.content,
                )
                limit_warned = True
            continue
        events.append(event)
    return events


def process_grouped_summary_detail(
    sd_config: SummaryDetailConfig,
    query_results: list[dict],
    add_detail_fn: Callable[[str, Optional[str], str], None],
):
    """Process a grouped summary detail config — collect lines into one detail."""
    # Jinja grouped mode: render the template once with all qualifying events
    if sd_config.format == SUMMARY_DETAIL_FORMAT_JINJA:
        events = collect_qualifying_events(sd_config, query_results)
        if not events:
            return

        content = render_jinja_template(
            sd_config.content,
            {"events": events},
            strict=(sd_config.required_fields is None),
        )
        if content is None or not content.strip():
            return

        header = None
        if sd_config.header is not None:
            header_ok, header = render_sd_header(sd_config, events[0])
            if not header_ok:
                header = None

        add_detail_fn(content, header, sd_config.format)
        return

    # Non-Jinja grouped mode: per-event render + join
    lines: list[str] = []
    header: Optional[str] = None
    limit_warned = False
    seen_keys: set[tuple] = set()

    for event in query_results:
        # required fields check
        if sd_config.required_fields is not None:
            if not event_has_required_fields(event, sd_config.required_fields):
                continue

        # dedup check
        if sd_config.dedup_fields is not None:
            dedup_key = compute_dedup_key(event, sd_config.dedup_fields)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

        content = render_sd_content(sd_config, event)
        if content is None:
            continue

        # resolve header from first contributing event only
        if header is None and sd_config.header is not None:
            header_ok, resolved_header = render_sd_header(sd_config, event)
            if header_ok:
                header = resolved_header

        if len(lines) >= sd_config.limit:
            if not limit_warned:
                logging.warning(
                    "summary detail limit (%s) reached for definition content=%s",
                    sd_config.limit, sd_config.content,
                )
                limit_warned = True
            continue

        lines.append(content)

    if lines:
        add_detail_fn("\n".join(lines), header, sd_config.format)
