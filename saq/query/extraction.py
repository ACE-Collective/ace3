# vim: sw=4:ts=4:et:cc=120

import datetime
import logging
import re
from dataclasses import dataclass
from typing import Callable, Optional

from pydantic import BaseModel, Field

from saq.analysis.observable import Observable
from saq.constants import F_FILE
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
)


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
        count = 0
        for event in query_results:
            content_values = interpolate_event_value(sd_config.content, event)
            if not content_values:
                continue
            content = content_values[0]
            if contains_unresolved_placeholders(content):
                continue

            header = None
            if sd_config.header is not None:
                header_values = interpolate_event_value(sd_config.header, event)
                if not header_values:
                    continue
                header = header_values[0]
                if contains_unresolved_placeholders(header):
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
