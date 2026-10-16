"""Hunt validation service (ACE API v2), shared with the legacy POST /api/hunt/validate.

A hunt's author (the validate-hunt CLI) sends a compiled hunt package; it is checked the way the
hunter would load it and, with execution_arguments, run against its data source, its results
optionally analyzed or turned into alerts. The response carries what the run produced and every
log line it wrote, which are kept off the production log handlers.

validate_hunt() is framework-free and synchronous: both the v2 route and the legacy Flask route
call it and answer with exactly its body and status, so the CLI can move to the v2 URL without any
other change. Every request leaves one HUNT_AUDIT record (aceapi_v2/hunt/audit.py).
"""

import hashlib
import logging
import shutil
import tempfile
import threading
from datetime import datetime
from typing import Any, Optional

import pytz
import yaml
from pydantic import BaseModel, ValidationError

from hunt_compiler import CompiledHunt, load_compiled_hunt
from aceapi_v2.hunt.audit import ValidationOutcome
from saq.analysis.root import RootAnalysis
from saq.collectors.hunter.correlation.command_types import load_command_types_from_config
from saq.collectors.hunter.correlation.sources import load_query_sources_from_config
from saq.collectors.hunter.correlation.validation import (
    check_custom_command_types,
    check_templates_for_removed_names,
)
from saq.collectors.hunter.loader import find_hunt_files_outside, get_compiled_hunt_dir, peek_hunt_type
from saq.collectors.hunter.query_hunter import QueryHunt
from saq.collectors.hunter.service import HunterService
from saq.constants import ANALYSIS_MODE_CORRELATION, QUEUE_DEFAULT, TAG_HUNT_VALIDATION
from saq.database.util.alert import ALERT
from saq.error.remote import RemoteApiError
from saq.logging import suppress_external_logging
from saq.util.uuid import storage_dir_from_uuid

class ListLogHandler(logging.Handler):
    """A logging handler that collects log records into a list.

    Only records emitted on the thread that constructed the handler are
    collected, so concurrent requests in the multi-threaded API process do not
    leak their log records into each other's collected list.
    """
    def __init__(self, log_list: list[logging.LogRecord]):
        super().__init__()
        self.log_list = log_list
        self.thread_id = threading.get_ident()
        self.setLevel(logging.INFO)

    def emit(self, record: logging.LogRecord):
        """Append the log record to the list if it was emitted on our thread."""
        if record.thread == self.thread_id:
            self.log_list.append(record)


class ExecutionArguments(BaseModel):
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    timezone: Optional[str] = None
    analyze_results: bool = False
    create_alerts: bool = False
    queue: str = QUEUE_DEFAULT
    # Optional override: when set, the hunt's data-source query is skipped and these
    # events are fed directly into process_query_results. Useful for iterating on
    # correlation logic against a previously captured event list. When provided,
    # start_time/end_time are not required.
    query_results: Optional[list[dict]] = None
    # Optional per-token TIMESPEC duration overrides. Maps token name to a duration
    # string in [D:][H:][M:]S format (e.g. "00:10:00"). Replaces the YAML-configured
    # duration_before for that token at execution time.
    time_range_overrides: Optional[dict[str, str]] = None
    # Optional saved correlate query results ({"version", "queries": [...]}). When set,
    # the correlation engine replays matching follow-up queries instead of re-running
    # them, so analysts can iterate on correlate logic / summary templates offline.
    correlate_results: Optional[dict] = None


def _query_text(hunt) -> Optional[str]:
    """The query a query hunt runs, for the audit record, or None when there is none."""
    if not isinstance(hunt, QueryHunt):
        return None

    try:
        return hunt.query
    except Exception:
        # a query that cannot be built fails the hunt's own execution, which reports why
        return None


def _validate_and_execute(target_file_path: str, package_dir: str, request_json: dict, audit: dict[str, Any],
                          requesting_user_id: Optional[int]) -> tuple[dict, int]:
    """Validate and optionally execute a hunt from its target file path.

    Args:
        target_file_path: the hunt YAML, inside package_dir
        package_dir: the directory the submitted package was materialized into; the hunt may name
            no file outside it
        request_json: the request body
        audit: filled in with what the request did, for the audit record
        requesting_user_id: the ACE user behind the request, who owns any alert it creates; None
            for a config API key

    Returns:
        (response body, status code).
    """
    # ensure correlation query sources and custom command types are registered before any hunt
    # execution. mocking HunterService in tests bypasses load_hunt_managers (the other call
    # site), so the validation API needs its own explicit trigger.
    load_query_sources_from_config()
    load_command_types_from_config()

    try:
        # the hunt is client-supplied: check that every file it names is part of its own package
        # before anything parses it for real
        outside = find_hunt_files_outside(target_file_path, package_dir)
        if outside:
            return {"valid": False, "error": "; ".join(outside)}, 400

        hunt_type = peek_hunt_type(target_file_path)
    except FileNotFoundError:
        return {"valid": False, "error": "target file not found"}, 400
    except yaml.YAMLError as e:
        return {"valid": False, "error": f"YAML syntax error: {e}"}, 400
    except ValueError as e:
        return {"valid": False, "error": f"invalid hunt config: {e}"}, 400

    # load it using the HuntManager
    hunter_service = HunterService()
    hunter_service.load_hunt_managers()
    try:
        manager = hunter_service.hunt_managers[hunt_type]
    except KeyError:
        return {"valid": False, "error": f"invalid hunt type {hunt_type}"}, 400

    # validate the hunt config with the appropriate class
    try:
        hunt = manager.load_hunt_from_config(target_file_path)
    except ValidationError as e:
        return {"valid": False, "error": f"invalid hunt config: {e}"}, 400

    audit["hunt"] = {"type": hunt_type, "name": hunt.name, "uuid": hunt.uuid}
    audit["query"] = _query_text(hunt)

    # catch a correlate template that reads _secrets or _config. neither is bound when a hunt
    # renders, so it would fail on every event in production; failing here says why.
    hunt_config = getattr(hunt, "config", None)
    template_errors = check_templates_for_removed_names(
        getattr(hunt_config, "correlate", None),
        getattr(hunt_config, "_predefined_commands", None),
    )
    if template_errors:
        return {"valid": False, "error": "; ".join(template_errors)}, 400

    # a custom command type that is not registered on this node (typo, or the integration is
    # missing) or whose options do not validate would otherwise only surface as a per-event step
    # error in production, which alerts every event.
    command_type_errors = check_custom_command_types(
        getattr(hunt_config, "correlate", None),
        getattr(hunt_config, "_predefined_commands", None),
    )
    if command_type_errors:
        return {"valid": False, "error": "; ".join(command_type_errors)}, 400

    # are we executing the hunt?
    execution_arguments_dict = request_json.get("execution_arguments", {})
    if not execution_arguments_dict:
        return {"valid": True}, 200

    try:
        execution_arguments = ExecutionArguments.model_validate(execution_arguments_dict)
    except ValidationError as e:
        return {"valid": False, "error": f"invalid execution_arguments: {e}"}, 400

    audit["execution"] = {
        "start_time": execution_arguments.start_time,
        "end_time": execution_arguments.end_time,
        "timezone": execution_arguments.timezone,
        "time_range_overrides": execution_arguments.time_range_overrides,
        "analyze_results": execution_arguments.analyze_results,
        "create_alerts": execution_arguments.create_alerts,
        "queue": execution_arguments.queue,
        # supplied events replace the data-source query; saved correlate results replace follow-ups
        "supplied_events": None if execution_arguments.query_results is None else len(execution_arguments.query_results),
        "correlate_replay": execution_arguments.correlate_results is not None,
    }

    exec_kwargs = {}
    use_query_results_override = execution_arguments.query_results is not None

    # Seed saved correlate query results for replay. Set on the hunt so it reaches the
    # correlation engine whether correlation runs via the query_results override path or
    # the normal hunt.execute() path (both funnel through process_query_results).
    if execution_arguments.correlate_results is not None:
        hunt._correlate_replay_results = execution_arguments.correlate_results.get("queries")

    if isinstance(hunt, QueryHunt) and not use_query_results_override:
        if execution_arguments.start_time is None:
            return {"valid": False, "error": "start_time is required for query hunts"}, 400

        if execution_arguments.end_time is None:
            return {"valid": False, "error": "end_time is required for query hunts"}, 400

        try:
            start_time = datetime.strptime(execution_arguments.start_time, '%m/%d/%Y:%H:%M:%S')
        except ValueError:
            return {"valid": False, "error": "invalid start_time format: expected MM/DD/YYYY:HH:MM:SS"}, 400

        try:
            end_time = datetime.strptime(execution_arguments.end_time, '%m/%d/%Y:%H:%M:%S')
        except ValueError:
            return {"valid": False, "error": "invalid end_time format: expected MM/DD/YYYY:HH:MM:SS"}, 400

        if execution_arguments.timezone is not None:
            try:
                tz = pytz.timezone(execution_arguments.timezone)
            except pytz.exceptions.UnknownTimeZoneError:
                return {"valid": False, "error": f"invalid timezone: '{execution_arguments.timezone}'"}, 400
            start_time = tz.localize(start_time)
            end_time = tz.localize(end_time)
        else:
            start_time = pytz.utc.localize(start_time)
            end_time = pytz.utc.localize(end_time)

        exec_kwargs['start_time'] = start_time
        exec_kwargs['end_time'] = end_time

        if execution_arguments.time_range_overrides is not None:
            exec_kwargs['time_range_overrides'] = execution_arguments.time_range_overrides

    # Set up logging handler to collect all logs
    collected_logs: list[logging.LogRecord] = []
    log_handler = ListLogHandler(collected_logs)
    root_logger = logging.getLogger()
    root_logger.addHandler(log_handler)

    try:
        try:
            hunt.manual_hunt = True
            # are we passing in the query results to use?
            if use_query_results_override:
                submissions = hunt.process_query_results(execution_arguments.query_results)
            else:
                submissions = hunt.execute(**exec_kwargs)
        except RemoteApiError as e:
            audit["event"] = "hunt_error"
            return {"valid": False, "error": e.message, "remote_status_code": e.status_code}, 400
        except Exception as e:
            audit["event"] = "hunt_error"
            return {"valid": False, "error": f"error executing hunt: {e}"}, 400

        if submissions is None:
            submissions = []

        roots: list[RootAnalysis] = []
        for submission in submissions:
            if execution_arguments.analyze_results or execution_arguments.create_alerts:
                # we duplicate because we could be sending multiple copies to multiple remote nodes
                new_root = submission.root.duplicate()
                new_root.move(storage_dir_from_uuid(new_root.uuid))
                new_root.queue = execution_arguments.queue
                # whatever this becomes lands in the same lists as the hunt's production alerts
                new_root.add_tag(TAG_HUNT_VALIDATION)
                new_root.save()

                # if we received a submission for correlation mode then we go ahead and add it to the database
                if execution_arguments.create_alerts:
                    new_root.analysis_mode = ANALYSIS_MODE_CORRELATION
                    # owned by the analyst running the validation, so a bulk action by someone
                    # else leaves it alone unless they choose to take it
                    ALERT(new_root, owner_id=requesting_user_id)

                new_root.schedule()
                roots.append(new_root)
            else:
                roots.append(submission.root)

        audit["result"] = {"roots": len(roots)}
        original_query_results = getattr(hunt, "original_query_results", None)
        if isinstance(original_query_results, list):
            audit["result"]["events"] = len(original_query_results)
        if execution_arguments.create_alerts:
            audit["result"]["alert_uuids"] = [root.uuid for root in roots]
        elif execution_arguments.analyze_results:
            audit["result"]["analysis_uuids"] = [root.uuid for root in roots]

        # a little quirck which how ACE works
        # the details are typically not loaded until they are needed
        # so we need to explicitly load them here

        root_json_results = []
        for root in roots:
            root_json = root.json
            # this forces the load and places the result in the json
            root_json["details"] = root.details
            root_json_results.append(root_json)

        log_format = '[%(asctime)s] [%(filename)s:%(lineno)d] [%(threadName)s] [%(process)d] [%(levelname)s] - %(message)s'
        log_formatter = logging.Formatter(log_format)
        formatted_logs = []
        for record in collected_logs:
            formatted_logs.append(log_formatter.format(record))

        correlation_trace = None
        if hasattr(hunt, "correlation_trace") and hunt.correlation_trace is not None:
            correlation_trace = hunt.correlation_trace.model_dump()

        original_events = None
        if getattr(hunt, "original_query_results", None) is not None:
            original_events = hunt.original_query_results

        return {
            "valid": True,
            "roots": root_json_results,
            "logs": formatted_logs,
            "correlation_trace": correlation_trace,
            "original_events": original_events,
            "correlate_results": getattr(hunt, "correlate_query_results", None),
        }, 200
    finally:
        root_logger.removeHandler(log_handler)


def _validate_request(request_json: Any, audit: dict[str, Any], requesting_user_id: Optional[int]) -> tuple[dict, int]:
    """Materialize the submitted hunt and validate (and optionally execute) it."""
    if not request_json or not isinstance(request_json, dict):
        return {"valid": False, "error": "request body must be JSON"}, 400

    if "compiled_hunt" not in request_json:
        return {"valid": False, "error": "missing 'compiled_hunt' field"}, 400

    try:
        compiled = CompiledHunt.model_validate(request_json["compiled_hunt"])
    except ValidationError as e:
        return {"valid": False, "error": f"invalid compiled_hunt: {e}"}, 400

    # the package as the client sent it, so what ran can be matched to a file in a hunt repository
    audit["package"] = {
        "target": compiled.target,
        "package_root": compiled.package_root,
        "assets": [
            {"path": asset.path, "kind": asset.kind, "sha256": hashlib.sha256(asset.content.encode()).hexdigest()}
            for asset in compiled.assets
        ],
    }

    temp_dir = tempfile.mkdtemp(dir=get_compiled_hunt_dir())

    try:
        try:
            logging.debug(
                "loading compiled hunt version=%s package_root=%s assets=%s",
                compiled.version,
                compiled.package_root,
                len(compiled.assets),
            )
            target_file_path = load_compiled_hunt(compiled, temp_dir)
        except Exception as e:
            return {"valid": False, "error": f"error loading compiled hunt: {e}"}, 400

        return _validate_and_execute(target_file_path, temp_dir, request_json, audit, requesting_user_id)
    finally:
        shutil.rmtree(temp_dir)


def validate_hunt(outcome: ValidationOutcome, request_json: Any, requesting_user_id: Optional[int]) -> None:
    """Validate, and optionally execute, the hunt in a request body, filling in outcome. Runs on
    the calling thread: the log capture and the suppression of the production handlers are both
    per thread. An unexpected exception propagates; the caller audits it as a 500
    (failure_audit_fields())."""
    with suppress_external_logging():
        outcome.body, outcome.status = _validate_request(request_json, outcome.audit, requesting_user_id)
