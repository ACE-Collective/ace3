# vim: sw=4:ts=4:et:cc=120
#
# ACE Hunting System - result processing mixin
#

import logging
import os
import os.path
from tempfile import mkstemp
from typing import Optional

from saq.analysis.observable import Observable
from saq.analysis.root import KEY_PLAYBOOK_URL, RootAnalysis, Submission
from saq.constants import F_SIGNATURE_ID
from saq.environment import get_temp_dir
from saq.gui.alert import KEY_ALERT_TEMPLATE, KEY_ICON_CONFIGURATION
from saq.observables.generator import create_observable
from saq.observables.mapping import RelationshipMapping
from saq.query.config import SummaryDetailConfig
from saq.query.event_processing import (
    contains_unresolved_placeholders,
    interpolate_event_value,
)
from saq.query.extraction import extract_observables_from_event
from saq.util import local_time

QUERY_DETAILS_SEARCH_ID = "search_id"
QUERY_DETAILS_SEARCH_LINK = "search_link"
QUERY_DETAILS_QUERY = "query"
QUERY_DETAILS_EVENTS = "events"


class ResultProcessingMixin:
    """Mixin that provides result processing logic for hunts that produce tabular/event results.

    Expects the following properties/attributes on the host class:
    - group_by, dedup_key, description_field, observable_mapping
    - uuid, name, config (with summary_details, _ignored_value_patterns, ignored_values)
    - playbook_url, icon_configuration, alert_template, tags, pivot_links
    - description, analysis_mode, type, tool_instance, alert_type, queue
    """

    # subclasses can set these to provide search context
    search_id: Optional[str] = None
    search_link: Optional[str] = None

    def formatted_query(self):
        """Formats query to a readable string. Return None if not applicable."""
        return None

    def extract_event_timestamp(self, query_result: dict):
        """Given a JSON object representing a single event, return a datetime or None."""
        return None

    def wrap_event(self, event):
        """Subclasses can override this to return an event object with additional capabilities."""
        return event

    def create_root_analysis(self, event: dict) -> RootAnalysis:
        import uuid as uuidlib
        root_uuid = str(uuidlib.uuid4())
        extensions = {}
        if self.playbook_url:
            for url_value in interpolate_event_value(self.playbook_url, event):
                extensions.update({
                    KEY_PLAYBOOK_URL: url_value,
                })

        if self.icon_configuration:
            extensions[KEY_ICON_CONFIGURATION] = self.icon_configuration.model_dump()

        if self.alert_template:
            extensions[KEY_ALERT_TEMPLATE] = self.alert_template

        root = RootAnalysis(
            uuid=root_uuid,
            storage_dir=os.path.join(get_temp_dir(), root_uuid),
            desc=self.name,
            instructions=self.description,
            analysis_mode=self.analysis_mode,
            tool=f"hunter-{self.type}",
            tool_instance=self.tool_instance,
            alert_type=self.alert_type,
            details={
                QUERY_DETAILS_SEARCH_ID: self.search_id if self.search_id else None,
                QUERY_DETAILS_SEARCH_LINK: self.search_link if self.search_link else None,
                QUERY_DETAILS_QUERY: self.formatted_query(),
                QUERY_DETAILS_EVENTS: [],
            },
            event_time=None,
            queue=self.queue,
            extensions=extensions)

        root.initialize_storage()

        for tag in self.tags:
            for tag_value in interpolate_event_value(tag, event):
                root.add_tag(tag_value)

        for pivot_link in self.pivot_links:
            for pivot_link_url_value in interpolate_event_value(pivot_link["url"], event):
                for pivot_link_text_value in interpolate_event_value(pivot_link["text"], event):
                    root.add_pivot_link(pivot_link_url_value, pivot_link.get("icon", None), pivot_link_text_value)

        return root

    def _process_summary_details(self, query_results: list[dict], event_submission_map: dict[int, list[Submission]]):
        """Process all summary_details definitions against the query results."""
        for sd_config in self.config.summary_details:
            if sd_config.grouped:
                self._process_grouped_summary_detail(sd_config, query_results, event_submission_map)
            else:
                self._process_ungrouped_summary_detail(sd_config, query_results, event_submission_map)

    def _process_ungrouped_summary_detail(
        self,
        sd_config: SummaryDetailConfig,
        query_results: list[dict],
        event_submission_map: dict[int, list[Submission]],
    ):
        """Add one SummaryDetail per event per submission for this definition."""
        count: dict[int, int] = {}  # submission id -> count

        for event_index, event in enumerate(query_results):
            if event_index not in event_submission_map:
                continue

            # interpolate content
            content_values = interpolate_event_value(sd_config.content, event)
            if not content_values:
                continue
            content = content_values[0]
            if contains_unresolved_placeholders(content):
                continue

            # interpolate header
            header = None
            if sd_config.header is not None:
                header_values = interpolate_event_value(sd_config.header, event)
                if not header_values:
                    continue
                header = header_values[0]
                if contains_unresolved_placeholders(header):
                    continue

            for submission in event_submission_map[event_index]:
                sub_id = id(submission)
                current_count = count.get(sub_id, 0)
                if current_count >= sd_config.limit:
                    if current_count == sd_config.limit:
                        logging.warning(
                            "summary detail limit (%s) reached for definition content=%s in hunt %s",
                            sd_config.limit, sd_config.content, self.name,
                        )
                        count[sub_id] = current_count + 1
                    continue
                submission.root.add_summary_detail(header=header, content=content, format=sd_config.format)
                count[sub_id] = current_count + 1

    def _process_grouped_summary_detail(
        self,
        sd_config: SummaryDetailConfig,
        query_results: list[dict],
        event_submission_map: dict[int, list[Submission]],
    ):
        """Collect content from all events and add one combined SummaryDetail per submission."""
        # submission id -> list of content strings
        collected: dict[int, list[str]] = {}
        # submission id -> header (from first contributing event)
        headers: dict[int, Optional[str]] = {}
        # submission id -> submission object
        sub_lookup: dict[int, Submission] = {}
        # submission id -> whether we've already logged the limit warning
        limit_warned: dict[int, bool] = {}

        for event_index, event in enumerate(query_results):
            if event_index not in event_submission_map:
                continue

            content_values = interpolate_event_value(sd_config.content, event)
            if not content_values:
                continue
            content = content_values[0]
            if contains_unresolved_placeholders(content):
                continue

            for submission in event_submission_map[event_index]:
                sub_id = id(submission)
                sub_lookup[sub_id] = submission

                if sub_id not in collected:
                    collected[sub_id] = []
                    limit_warned[sub_id] = False

                if len(collected[sub_id]) >= sd_config.limit:
                    if not limit_warned[sub_id]:
                        logging.warning(
                            "summary detail limit (%s) reached for grouped definition content=%s in hunt %s",
                            sd_config.limit, sd_config.content, self.name,
                        )
                        limit_warned[sub_id] = True
                    continue

                collected[sub_id].append(content)

                # resolve header from first contributing event
                if sub_id not in headers:
                    if sd_config.header is not None:
                        header_values = interpolate_event_value(sd_config.header, event)
                        if header_values and not contains_unresolved_placeholders(header_values[0]):
                            headers[sub_id] = header_values[0]
                        else:
                            headers[sub_id] = None
                    else:
                        headers[sub_id] = None

        # add the combined summary details
        for sub_id, lines in collected.items():
            if not lines:
                continue
            submission = sub_lookup[sub_id]
            submission.root.add_summary_detail(
                header=headers.get(sub_id),
                content="\n".join(lines),
                format=sd_config.format,
            )

    def process_query_results(self, query_results, **kwargs) -> Optional[list[Submission]]:
        if query_results is None:
            return None

        submissions: list[Submission] = []  # of Submission objects

        def _create_submission(event: dict):
            return Submission(self.create_root_analysis(event))

        def _compute_dedup_key(event: dict) -> Optional[str]:
            if not self.dedup_key:
                return None
            values = interpolate_event_value(self.dedup_key, event)
            if not values:
                return None
            value = values[0]
            if contains_unresolved_placeholders(value):
                return None
            return f"{self.uuid}:{value}"

        event_grouping = {}  # key = self.group_by field value, value = Submission

        # this is used to keep track of which observables need to have relationship mapped
        relationship_tracking: dict[Observable, list[RelationshipMapping]] = {}

        # maps event index to the submission(s) it belongs to (for summary detail processing)
        event_submission_map: dict[int, list[Submission]] = {}

        # map results to observables
        for event_index, event in enumerate(query_results):
            event_time = self.extract_event_timestamp(event) or local_time()
            event = self.wrap_event(event)

            # use shared extraction pipeline
            extracted, file_contents, event_relationships = extract_observables_from_event(
                event, self.observable_mapping, event_time,
                global_ignored_patterns=self.config._ignored_value_patterns if self.config.ignored_values else None,
            )

            # deduplicate observables (shared extraction may return duplicates across mappings)
            observables: list[Observable] = []
            for ext in extracted:
                if ext.observable not in observables:
                    observables.append(ext.observable)

            # merge relationship tracking
            relationship_tracking.update(event_relationships)

            signature_id_observable = create_observable(F_SIGNATURE_ID, self.uuid)

            if signature_id_observable is not None:
                signature_id_observable.display_value = self.name
                observables.append(signature_id_observable)

            # if we are NOT grouping then each row is an alert by itself
            if self.group_by != "ALL" and (self.group_by is None or self.group_by not in event):
                submission = _create_submission(event)
                submission.key = _compute_dedup_key(event)
                submission.root.event_time = event_time

                if self.description_field is not None and self.description_field in event:
                    description_value = event[self.description_field]
                    if isinstance(description_value, list):
                        description_value = description_value[0] if description_value else ""
                    if description_value:
                        submission.root.description += f": {description_value}"

                for observable in observables:
                    submission.root.add_observable(observable)

                for file_content in file_contents:
                    fd, temp_file_path = mkstemp(dir=get_temp_dir())
                    os.write(fd, file_content.content)
                    os.close(fd)

                    file_obs = submission.root.add_file_observable(temp_file_path, target_path=file_content.file_name, move=True, volatile=file_content.volatile)
                    for directive in file_content.directives:
                        file_obs.add_directive(directive)
                    for tag in file_content.tags:
                        file_obs.add_tag(tag)
                    if file_content.display_type is not None:
                        file_obs.display_type = file_content.display_type

                submission.root.details[QUERY_DETAILS_EVENTS].append(event)
                submissions.append(submission)
                event_submission_map[event_index] = [submission]

            # if we are grouping then we start pulling all the data into groups
            else:
                # if we're grouping all results together then there's only a single group
                grouping_targets = ["ALL" if self.group_by == "ALL" else event[self.group_by]]
                if self.group_by != "ALL":
                    if isinstance(event[self.group_by], list):
                        grouping_targets = event[self.group_by]

                for grouping_target in grouping_targets:
                    if grouping_target not in event_grouping:
                        event_grouping[grouping_target] = _create_submission(event)
                        event_grouping[grouping_target].key = _compute_dedup_key(event)
                        if grouping_target != "ALL":
                            if self.description_field is not None and self.description_field in event:
                                description_value = event[self.description_field]
                                if isinstance(description_value, list):
                                    description_value = description_value[0] if description_value else grouping_target
                                event_grouping[grouping_target].root.description += f": {description_value}"
                            else:
                                event_grouping[grouping_target].root.description += f": {grouping_target}"
                        submissions.append(event_grouping[grouping_target])

                    for observable in observables:
                        if observable not in event_grouping[grouping_target].root.observables:
                            event_grouping[grouping_target].root.add_observable(observable)

                    for file_content in file_contents:
                        fd, temp_file_path = mkstemp(dir=get_temp_dir())
                        os.write(fd, file_content.content)
                        os.close(fd)

                        file_obs = event_grouping[grouping_target].root.add_file_observable(temp_file_path, target_path=file_content.file_name, move=True, volatile=file_content.volatile)
                        for directive in file_content.directives:
                            file_obs.add_directive(directive)
                        for tag in file_content.tags:
                            file_obs.add_tag(tag)
                        if file_content.display_type is not None:
                            file_obs.display_type = file_content.display_type

                    event_grouping[grouping_target].root.details[QUERY_DETAILS_EVENTS].append(event)
                    event_submission_map.setdefault(event_index, []).append(event_grouping[grouping_target])

                    # for grouped events, the overall event time is the earliest event time in the group
                    if event_grouping[grouping_target].root.event_time is None:
                        event_grouping[grouping_target].root.event_time = event_time
                    elif event_time < event_grouping[grouping_target].root.event_time:
                        event_grouping[grouping_target].root.event_time = event_time

            # apply relationships to the observables
            for submission in submissions:
                for observable in submission.root.observables:
                    if observable in relationship_tracking:
                        for relationship_mapping in relationship_tracking[observable]:
                            for potential_target_value in interpolate_event_value(relationship_mapping.target.value, event):
                                if contains_unresolved_placeholders(potential_target_value):
                                    logging.warning(
                                        f"skipping relationship in hunt {self.name}: target value "
                                        f"'{relationship_mapping.target.value}' resolved to '{potential_target_value}' "
                                        f"which contains unresolved field references (field missing from event)"
                                    )
                                    continue
                                target_observable = submission.root.get_observable_by_spec(relationship_mapping.target.type, potential_target_value)
                                if target_observable is not None:
                                    observable.add_relationship(relationship_mapping.type, target_observable)

        # update the descriptions of grouped alerts with the event counts
        if self.group_by is not None:
            for submission in submissions:
                submission.root.description += f' ({len(submission.root.details.get(QUERY_DETAILS_EVENTS, []))} event{"" if len(submission.root.details.get(QUERY_DETAILS_EVENTS, [])) == 1 else "s"})'

        self._process_summary_details(query_results, event_submission_map)

        return submissions
