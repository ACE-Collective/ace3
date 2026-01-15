import logging
import os
import shutil
import tempfile

import yaml
from flask import jsonify, request
from pydantic import ValidationError

from aceapi.auth import api_auth_check
from aceapi.blueprints import hunt_bp
from saq.collectors.hunter.base_hunter import HuntConfig
from saq.collectors.hunter.loader import load_from_yaml
from saq.collectors.hunter.service import HunterService
from saq.environment import get_temp_dir

def _validate_hunt_file_path(file_path: str) -> str:
    if os.path.isabs(file_path):
        raise ValueError(f"hunt file path {file_path} is absolute, but must be relative")
    
    # Ensure the file_path does not include ".." as a directory traversal,
    # but allow ".." if it appears as part of a filename (not as a path segment)
    path_parts = file_path.replace("\\", "/").split("/")
    if any(part == ".." for part in path_parts[:-1]):
        raise ValueError(f"hunt file path {file_path} contains prohibited parent directory traversal '..' in path segments")

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
            return jsonify({"valid": False, "error": f"target file '{target}' not found"}), 200
        except yaml.YAMLError as e:
            return jsonify({"valid": False, "error": f"YAML syntax error: {e}"}), 200
        except ValidationError as e:
            return jsonify({"valid": False, "error": f"invalid hunt config: {e}"}), 200

        # load it using the HuntManager
        hunter_service = HunterService()
        hunter_service.load_hunt_managers()
        try:
            manager = hunter_service.hunt_managers[hunt_dict.type_]
        except KeyError:
            return jsonify({"valid": False, "error": f"invalid hunt type {hunt_dict.type_}"}), 200

        # validate the hunt config with the appropriate class
        try:
            hunt = manager.load_hunt_from_config(target_file_path)
        except ValidationError as e:
            return jsonify({"valid": False, "error": f"invalid hunt config: {e}"}), 200

    finally:
        shutil.rmtree(temp_dir)

    return jsonify({"valid": True}), 200