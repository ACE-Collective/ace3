from datetime import datetime
import logging
import os
import shutil
import tempfile
import threading
from typing import Optional

import pytz
import yaml
from flask import request
from pydantic import BaseModel, ValidationError

from aceapi.auth import api_auth_check
from aceapi.json import json_result
from aceapi.blueprints import hunt_bp
from hunt_compiler import CompiledHunt, load_compiled_hunt
from saq.analysis.root import RootAnalysis
from saq.collectors.hunter.correlation.sources import load_query_sources_from_config
from saq.collectors.hunter.correlation.validation import check_env_for_encrypted_markers
from saq.collectors.hunter.loader import peek_hunt_type
from saq.collectors.hunter.query_hunter import QueryHunt
from saq.collectors.hunter.service import HunterService
from saq.configuration import get_config
from saq.constants import ANALYSIS_MODE_CORRELATION, QUEUE_DEFAULT
from saq.error.remote import RemoteApiError
from saq.database.util.alert import ALERT
from saq.environment import get_data_dir
from saq.logging import suppress_external_logging
from saq.util.uuid import storage_dir_from_uuid


def get_compiled_hunt_dir() -> str:
    """Return a directory for compiled hunt temp files that supports execution.

    The default temp directory (/tmp) may be mounted as a noexec tmpfs in Docker,
    preventing extracted scripts from being executed. This uses a configurable
    subdirectory under the data directory instead.
    """
    path = os.path.join(get_data_dir(), get_config().global_settings.compiled_hunt_dir)
    os.makedirs(path, exist_ok=True)
    return path


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


def _validate_and_execute(target_file_path: str, request_json: dict):
    """Validate and optionally execute a hunt from its target file path.

    Returns:
        Flask response tuple (response, status_code).
    """
    # ensure correlation query sources are registered before any hunt execution.
    # mocking HunterService in tests bypasses load_hunt_managers (the other call
    # site), so the validation API needs its own explicit trigger.
    load_query_sources_from_config()

    try:
        hunt_type = peek_hunt_type(target_file_path)
    except FileNotFoundError:
        return json_result({"valid": False, "error": "target file not found"}), 400
    except yaml.YAMLError as e:
        return json_result({"valid": False, "error": f"YAML syntax error: {e}"}), 400
    except ValueError as e:
        return json_result({"valid": False, "error": f"invalid hunt config: {e}"}), 400

    # load it using the HuntManager
    hunter_service = HunterService()
    hunter_service.load_hunt_managers()
    try:
        manager = hunter_service.hunt_managers[hunt_type]
    except KeyError:
        return json_result({"valid": False, "error": f"invalid hunt type {hunt_type}"}), 400

    # validate the hunt config with the appropriate class
    try:
        hunt = manager.load_hunt_from_config(target_file_path)
    except ValidationError as e:
        return json_result({"valid": False, "error": f"invalid hunt config: {e}"}), 400

    # catch a correlate command that tries to read an encrypted secret through _config, which
    # renders the marker rather than the credential. the runtime guard in commands.py also
    # covers this, but failing here means it never reaches production.
    hunt_config = getattr(hunt, "config", None)
    env_errors = check_env_for_encrypted_markers(
        getattr(hunt_config, "correlate", None),
        getattr(hunt_config, "_predefined_commands", None),
    )
    if env_errors:
        return json_result({"valid": False, "error": "; ".join(env_errors)}), 400

    # are we executing the hunt?
    execution_arguments_dict = request_json.get("execution_arguments", {})
    if not execution_arguments_dict:
        return json_result({"valid": True}), 200

    try:
        execution_arguments = ExecutionArguments.model_validate(execution_arguments_dict)
    except ValidationError as e:
        return json_result({"valid": False, "error": f"invalid execution_arguments: {e}"}), 400

    exec_kwargs = {}
    use_query_results_override = execution_arguments.query_results is not None

    # Seed saved correlate query results for replay. Set on the hunt so it reaches the
    # correlation engine whether correlation runs via the query_results override path or
    # the normal hunt.execute() path (both funnel through process_query_results).
    if execution_arguments.correlate_results is not None:
        hunt._correlate_replay_results = execution_arguments.correlate_results.get("queries")

    if isinstance(hunt, QueryHunt) and not use_query_results_override:
        if execution_arguments.start_time is None:
            return json_result({"valid": False, "error": "start_time is required for query hunts"}), 400

        if execution_arguments.end_time is None:
            return json_result({"valid": False, "error": "end_time is required for query hunts"}), 400

        try:
            start_time = datetime.strptime(execution_arguments.start_time, '%m/%d/%Y:%H:%M:%S')
        except ValueError:
            return json_result({"valid": False, "error": "invalid start_time format: expected MM/DD/YYYY:HH:MM:SS"}), 400

        try:
            end_time = datetime.strptime(execution_arguments.end_time, '%m/%d/%Y:%H:%M:%S')
        except ValueError:
            return json_result({"valid": False, "error": "invalid end_time format: expected MM/DD/YYYY:HH:MM:SS"}), 400

        if execution_arguments.timezone is not None:
            try:
                tz = pytz.timezone(execution_arguments.timezone)
            except pytz.exceptions.UnknownTimeZoneError:
                return json_result({"valid": False, "error": f"invalid timezone: '{execution_arguments.timezone}'"}), 400
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
            return json_result({"valid": False, "error": e.message, "remote_status_code": e.status_code}), 400
        except Exception as e:
            return json_result({"valid": False, "error": f"error executing hunt: {e}"}), 400

        if submissions is None:
            submissions = []

        roots: list[RootAnalysis] = []
        for submission in submissions:
            if execution_arguments.analyze_results or execution_arguments.create_alerts:
                # we duplicate because we could be sending multiple copies to multiple remote nodes
                new_root = submission.root.duplicate()
                new_root.move(storage_dir_from_uuid(new_root.uuid))
                new_root.queue = execution_arguments.queue
                new_root.save()

                # if we received a submission for correlation mode then we go ahead and add it to the database
                if execution_arguments.create_alerts:
                    new_root.analysis_mode = ANALYSIS_MODE_CORRELATION
                    ALERT(new_root)

                new_root.schedule()
                roots.append(new_root)
            else:
                roots.append(submission.root)

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

        return json_result({
            "valid": True,
            "roots": root_json_results,
            "logs": formatted_logs,
            "correlation_trace": correlation_trace,
            "original_events": original_events,
            "correlate_results": getattr(hunt, "correlate_query_results", None),
        }), 200
    finally:
        root_logger.removeHandler(log_handler)


@hunt_bp.route('/validate', methods=['POST'])
@api_auth_check("hunt", "write")
def validate_hunt():
    with suppress_external_logging():
        if not request.json:
            return json_result({"valid": False, "error": "request body must be JSON"}), 400

        if "compiled_hunt" not in request.json:
            return json_result({"valid": False, "error": "missing 'compiled_hunt' field"}), 400

        try:
            compiled = CompiledHunt.model_validate(request.json["compiled_hunt"])
        except ValidationError as e:
            return json_result({"valid": False, "error": f"invalid compiled_hunt: {e}"}), 400

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
                return json_result({"valid": False, "error": f"error loading compiled hunt: {e}"}), 400

            return _validate_and_execute(target_file_path, request.json)
        finally:
            shutil.rmtree(temp_dir)
