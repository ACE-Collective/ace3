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
from saq.observables.type_hierarchy import get_all_valid_types
from saq.query.config import SummaryDetailConfig
from saq.query.decoder import decode_value
from saq.query.field_lookup import FIELD_LOOKUP_TYPE_KEY, extract_event_value
from saq.query.summary_detail_rendering import render_jinja_template
from saq.query.template_rendering import (
    render_event_template,
    render_event_template_multi,
)


def _is_blank_value(value) -> bool:
    """A field counts as absent for mapping resolution if it is None, an empty/whitespace
    string, or an empty collection — matching resolve_fields' 'present and non-null' contract."""
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return False


def _interpolate_strict(template: str, event: dict) -> list[str]:
    """Strict-mode multi-render that rejects the whole template on any missing field.

    Returns an empty list if any referenced field is absent from the event, so
    callers can iterate the result and naturally skip entries whose template
    couldn't fully resolve. This matches the legacy
    `contains_unresolved_placeholders` guard semantics on top of Jinja.
    """
    try:
        return render_event_template_multi(template, event, strict=True)
    except UndefinedError:
        return []


def _resolve_mapping_type(mapping: ObservableMapping, event: dict) -> Optional[str]:
    """Render a Jinja-templated observable type against the event.

    Returns the lowercased resolved type, or None to skip this mapping for
    this event. Missing fields skip silently (matching value-template
    semantics). A resolution that is unusable (unknown type, or resolved to
    F_FILE, which requires static file_name handling) logs at error level and
    falls back to mapping.fallback_type if configured and itself valid;
    otherwise the mapping is skipped.
    """
    try:
        rendered = render_event_template(mapping.type, event, strict=True)
    except UndefinedError:
        return None  # missing field — silent, like _interpolate_strict
    if rendered is None:
        return None  # syntax error — already error-logged by render_jinja_template

    resolved = rendered.strip().lower()
    valid_types = get_all_valid_types()
    if resolved != F_FILE and resolved in valid_types:
        return resolved

    if mapping.fallback_type is not None:
        if mapping.fallback_type in valid_types:
            logging.error(
                "observable mapping type template %r resolved to unusable observable type %r "
                "— using fallback_type %r",
                mapping.type, resolved, mapping.fallback_type)
            return mapping.fallback_type
        logging.error(
            "observable mapping type template %r resolved to unusable observable type %r "
            "and fallback_type %r is not a defined observable type — skipping",
            mapping.type, resolved, mapping.fallback_type)
        return None

    logging.error(
        "observable mapping type template %r resolved to unknown observable type %r — skipping",
        mapping.type, resolved)
    return None


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
        # then we just take the value using the configured lookup type
        field_name = field_override if field_override is not None else observable_mapping.fields[0]
        success, observed_value = extract_event_value(
            event, observable_mapping.field_lookup_type, field_name
        )
        if not success:
            raise KeyError(field_name)
    else:
        # otherwise we interpolate the value from the event; strict mode means
        # a missing field rejects the whole template entry (no observable created)
        observed_value = _interpolate_strict(observable_mapping.value, event)

    # we always return a list of values, even if there is only one
    if not isinstance(observed_value, list):
        result = [observed_value]
    else:
        result = observed_value

    # cap how many observables this mapping emits from a list-valued field, a
    # '*' wildcard path, or a Jinja value template that expanded to many values
    if observable_mapping.limit is not None:
        result = result[: observable_mapping.limit]

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
                success, value = extract_event_value(_event, _mapping.field_lookup_type, field_name)
                return success and not _is_blank_value(value)
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
    resolved_type = mapping.type
    if mapping.type_is_templated:
        resolved_type = _resolve_mapping_type(mapping, event)
        if resolved_type is None:
            return

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

        if resolved_type == F_FILE:
            if mapping.file_decoder is not None:
                decoded_observed_value = decode_value(observed_value, mapping.file_decoder)

            if decoded_observed_value is None:
                decoded_observed_value = observed_value.encode('utf-8')

            # Strict mode: a missing field rejects the entire file_name template
            # (empty list → no FileContent emitted). For per-file directives/tags,
            # a missing field rejects just that template entry, not its siblings.
            for target_file_name in _interpolate_strict(mapping.file_name, event):
                if not target_file_name:
                    continue

                interpolated_directives = []
                for directive in mapping.directives:
                    for directive_value in _interpolate_strict(directive, event):
                        if directive_value:
                            interpolated_directives.append(directive_value)

                interpolated_tags = []
                for tag in mapping.tags:
                    for tag_value in _interpolate_strict(tag, event):
                        if tag_value:
                            interpolated_tags.append(tag_value)

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
            final_value = value_filter(matched_field, resolved_type, observed_value)

        observable = create_observable(resolved_type, final_value, volatile=mapping.volatile)

        if observable is None:
            logging.warning(
                f"unable to create observable {resolved_type} with value {final_value}"
            )
            continue

        if mapping.time and event_time is not None:
            observable.time = event_time

        apply_mapping_properties(observable, mapping,
                                 interpolate_fn=_interpolate_strict, event=event)

        if mapping.relationships:
            relationship_tracking[observable] = mapping.relationships

        extracted.append(ExtractedObservable(
            observable=observable,
            mapping=mapping,
            matched_field=matched_field,
        ))


def _required_value_is_empty(value) -> bool:
    """A required field counts as missing when its value is blank/empty.

    None, empty/whitespace-only strings, and empty list/dict/tuple/set are
    treated as empty. Numeric 0 and boolean False are real values (present).
    """
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    if isinstance(value, (list, dict, tuple, set)):
        return len(value) == 0
    return False


def event_has_required_fields(event: dict, required_fields: list[str]) -> bool:
    """Check that each required field is present AND non-empty.

    A field that is absent, None, an empty string, or an empty
    list/dict/tuple/set does not satisfy the requirement — the event is
    skipped. Numeric 0 / boolean False count as present.
    """
    for field_spec in required_fields:
        success, value = extract_event_value(event, FIELD_LOOKUP_TYPE_KEY, field_spec)
        if not success or _required_value_is_empty(value):
            return False
    return True


def compute_dedup_key(event: dict, dedup_fields: list[str]) -> tuple:
    """Build a dedup key tuple from the event values for each dedup field."""
    parts = []
    for field_spec in dedup_fields:
        success, value = extract_event_value(event, FIELD_LOOKUP_TYPE_KEY, field_spec)
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
    try:
        if sd_config.format == SUMMARY_DETAIL_FORMAT_JINJA:
            return render_jinja_template(sd_config.content, event, strict=strict)
        return render_event_template(sd_config.content, event, strict=strict)
    except UndefinedError:
        return None


def render_sd_header(sd_config: SummaryDetailConfig, event: dict) -> tuple[bool, Optional[str]]:
    """Render summary detail header for a single event.

    Returns (success, header). success=False means skip the event.
    """
    if sd_config.header is None:
        return (True, None)

    strict = sd_config.required_fields is None
    try:
        if sd_config.format == SUMMARY_DETAIL_FORMAT_JINJA:
            rendered = render_jinja_template(sd_config.header, event, strict=strict)
        else:
            rendered = render_event_template(sd_config.header, event, strict=strict)
    except UndefinedError:
        return (False, None)
    if rendered is None:
        return (False, None)
    return (True, rendered)


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

        # a header that cannot be rendered is not worth discarding content over — both
        # grouped paths below already degrade to a headerless detail
        header_ok, header = render_sd_header(sd_config, event)
        if not header_ok:
            header = None

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

        # A missing field under strict mode raises UndefinedError. Mirror render_sd_content
        # and skip just this block (rather than letting the error kill the whole analysis).
        try:
            content = render_jinja_template(
                sd_config.content,
                {"events": events},
                strict=(sd_config.required_fields is None),
            )
        except UndefinedError:
            logging.warning(
                "grouped jinja summary detail skipped (missing field) for content=%s",
                sd_config.content, exc_info=True,
            )
            return
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
                logging.error(
                    "summary detail limit (%s) reached for definition content=%s",
                    sd_config.limit, sd_config.content,
                )
                limit_warned = True
            continue

        lines.append(content)

    if lines:
        add_detail_fn("\n".join(lines), header, sd_config.format)
