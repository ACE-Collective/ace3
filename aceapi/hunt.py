from datetime import datetime
import logging
import os
import shutil
import tempfile
from typing import List, Optional

import pytz
import yaml
from flask import jsonify, request
from pydantic import BaseModel, ValidationError

from aceapi.auth import api_auth_check
from aceapi.blueprints import hunt_bp
from saq.analysis.root import RootAnalysis
from saq.collectors.hunter.base_hunter import HuntConfig
from saq.collectors.hunter.loader import load_from_yaml
from saq.collectors.hunter.query_hunter import QueryHunt
from saq.collectors.hunter.service import HunterService
from saq.constants import ANALYSIS_MODE_CORRELATION, QUEUE_DEFAULT
from saq.database.util.alert import ALERT
from saq.environment import get_temp_dir
from saq.util.uuid import storage_dir_from_uuid

class ListLogHandler(logging.Handler):
    """A logging handler that collects log records into a list."""
    def __init__(self, log_list: List[logging.LogRecord]):
        super().__init__()
        self.log_list = log_list
        self.setLevel(logging.INFO)
    
    def emit(self, record: logging.LogRecord):
        """Append the log record to the list."""
        self.log_list.append(record)

def _validate_hunt_file_path(file_path: str) -> str:
    if os.path.isabs(file_path):
        raise ValueError(f"hunt file path {file_path} is absolute, but must be relative")
    
    # Ensure the file_path does not include ".." as a directory traversal,
    # but allow ".." if it appears as part of a filename (not as a path segment)
    path_parts = file_path.replace("\\", "/").split("/")
    if any(part == ".." for part in path_parts[:-1]):
        raise ValueError(f"hunt file path {file_path} contains prohibited parent directory traversal '..' in path segments")

class ExecutionArguments(BaseModel):
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    timezone: Optional[str] = None
    analyze_results: bool = False
    create_alerts: bool = False
    queue: str = QUEUE_DEFAULT

@hunt_bp.route('/validate', methods=['POST'])
@api_auth_check("hunt", "write")
def validate_hunt():
    # Input validation
    if not request.json:
        return jsonify({"valid": False, "error": "request body must be JSON"}), 400
    
    if "hunts" not in request.json:
        return jsonify({"valid": False, "error": "missing 'hunts' field"}), 400
    
    if "target" not in request.json:
        return jsonify({"valid": False, "error": "missing 'target' field"}), 400
    
    hunts = request.json["hunts"]
    if not isinstance(hunts, list):
        return jsonify({"valid": False, "error": "'hunts' must be a list"}), 400
    
    target = request.json["target"]
    if not isinstance(target, str):
        return jsonify({"valid": False, "error": "'target' must be a string"}), 400
    
    # Validate target path
    try:
        _validate_hunt_file_path(target)
    except ValueError as e:
        return jsonify({"valid": False, "error": str(e)}), 400
    
    # create a temporary directory to store the hunt content
    temp_dir = tempfile.mkdtemp(dir=get_temp_dir())

    try:
        for hunt in hunts:
            if not isinstance(hunt, dict):
                return jsonify({"valid": False, "error": "each hunt must be a dictionary"}), 400
            
            if "file_path" not in hunt:
                return jsonify({"valid": False, "error": "each hunt must have a 'file_path' field"}), 400
            
            if "content" not in hunt:
                return jsonify({"valid": False, "error": "each hunt must have a 'content' field"}), 400
            
            if not isinstance(hunt["file_path"], str):
                return jsonify({"valid": False, "error": "hunt 'file_path' must be a string"}), 400
            
            if not isinstance(hunt["content"], str):
                return jsonify({"valid": False, "error": "hunt 'content' must be a string"}), 400
            
            try:
                _validate_hunt_file_path(hunt["file_path"])
            except ValueError as e:
                return jsonify({"valid": False, "error": str(e)}), 400
            
            hunt_path = os.path.join(temp_dir, hunt["file_path"])
            # Normalize path and verify it stays within temp_dir
            hunt_path = os.path.normpath(hunt_path)
            if not hunt_path.startswith(os.path.abspath(temp_dir) + os.sep) and hunt_path != os.path.abspath(temp_dir):
                return jsonify({"valid": False, "error": f"hunt file path {hunt['file_path']} is outside allowed directory"}), 400
            
            os.makedirs(os.path.dirname(hunt_path), exist_ok=True)
            logging.info(f"writing hunt content to {hunt_path}")
            with open(hunt_path, "w") as fp:
                fp.write(hunt["content"])

        target_file_path = os.path.join(temp_dir, target)
        # Normalize path and verify it stays within temp_dir
        target_file_path = os.path.normpath(target_file_path)
        if not target_file_path.startswith(os.path.abspath(temp_dir) + os.sep) and target_file_path != os.path.abspath(temp_dir):
            return jsonify({"valid": False, "error": f"target path {target} is outside allowed directory"}), 400

        try:
            hunt_dict, _ = load_from_yaml(target_file_path, HuntConfig)
        except FileNotFoundError:
            return jsonify({"valid": False, "error": f"target file '{target}' not found"}), 400
        except yaml.YAMLError as e:
            return jsonify({"valid": False, "error": f"YAML syntax error: {e}"}), 400
        except ValidationError as e:
            return jsonify({"valid": False, "error": f"invalid hunt config: {e}"}), 400

        # load it using the HuntManager
        hunter_service = HunterService()
        hunter_service.load_hunt_managers()
        try:
            manager = hunter_service.hunt_managers[hunt_dict.type_]
        except KeyError:
            return jsonify({"valid": False, "error": f"invalid hunt type {hunt_dict.type_}"}), 400

        # validate the hunt config with the appropriate class
        try:
            hunt = manager.load_hunt_from_config(target_file_path)
        except ValidationError as e:
            return jsonify({"valid": False, "error": f"invalid hunt config: {e}"}), 400

        # are we executing the hunt?
        execution_arguments_dict = request.json.get("execution_arguments", {})
        if execution_arguments_dict:
            try:
                execution_arguments = ExecutionArguments.model_validate(execution_arguments_dict)
            except ValidationError as e:
                return jsonify({"valid": False, "error": f"invalid execution_arguments: {e}"}), 400

            exec_kwargs = {}

            if isinstance(hunt, QueryHunt):
                if execution_arguments.start_time is None:
                    return jsonify({"valid": False, "error": "start_time is required for query hunts"}), 400

                if execution_arguments.end_time is None:
                    return jsonify({"valid": False, "error": "end_time is required for query hunts"}), 400

                try:
                    start_time = datetime.strptime(execution_arguments.start_time, '%m/%d/%Y:%H:%M:%S')
                except ValueError:
                    return jsonify({"valid": False, "error": "invalid start_time format: expected MM/DD/YYYY:HH:MM:SS"}), 400

                try:
                    end_time = datetime.strptime(execution_arguments.end_time, '%m/%d/%Y:%H:%M:%S')
                except ValueError:
                    return jsonify({"valid": False, "error": "invalid end_time format: expected MM/DD/YYYY:HH:MM:SS"}), 400

                if execution_arguments.timezone is not None:
                    try:
                        tz = pytz.timezone(execution_arguments.timezone)
                    except pytz.exceptions.UnknownTimeZoneError:
                        return jsonify({"valid": False, "error": f"invalid timezone: '{execution_arguments.timezone}'"}), 400
                    start_time = tz.localize(start_time)
                    end_time = tz.localize(end_time)
                else:
                    start_time = pytz.utc.localize(start_time)
                    end_time = pytz.utc.localize(end_time)

                exec_kwargs['start_time'] = start_time
                exec_kwargs['end_time'] = end_time

            # Set up logging handler to collect all logs
            collected_logs: List[logging.LogRecord] = []
            log_handler = ListLogHandler(collected_logs)
            root_logger = logging.getLogger()
            root_logger.addHandler(log_handler)
            
            try:
                try:
                    submissions = hunt.execute(**exec_kwargs)
                except Exception as e:
                    return jsonify({"valid": False, "error": f"error executing hunt: {e}"}), 400

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

                return jsonify({"valid": True, "roots": root_json_results, "logs": formatted_logs}), 200
            finally:
                root_logger.removeHandler(log_handler)

    finally:
        shutil.rmtree(temp_dir)

    return jsonify({"valid": True}), 200