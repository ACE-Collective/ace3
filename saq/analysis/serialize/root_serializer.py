import json
import logging
import shutil
from typing import TYPE_CHECKING

import dateutil.parser

from saq.analysis.io_tracking import _track_reads, _track_writes
from saq.json_encoding import _JSONEncoder
from saq.util import parse_event_time

# json keys
KEY_ANALYSIS_MODE = 'analysis_mode'
KEY_ID = 'id'
KEY_UUID = 'uuid'
KEY_TOOL = 'tool'
KEY_TOOL_INSTANCE = 'tool_instance'
KEY_TYPE = 'type'
KEY_DESCRIPTION = 'description'
KEY_EVENT_TIME = 'event_time'
KEY_ACTION_COUNTERS = 'action_counters'
KEY_DETAILS = 'details'
KEY_OBSERVABLE_STORE = 'observable_store'
KEY_NAME = 'name'
KEY_REMEDIATION = 'remediation'
KEY_STATE = 'state'
KEY_LOCATION = 'location'
KEY_NETWORK = 'network'
KEY_COMPANY_NAME = 'company_name'
KEY_COMPANY_ID = 'company_id'
KEY_DELAYED_ANALYSIS_TRACKING = 'delayed_analysis_tracking'
KEY_DEPENDECY_TRACKING = 'dependency_tracking'
KEY_QUEUE = 'queue'
KEY_INSTRUCTIONS = 'instructions'
KEY_ANALYSIS_FAILURES = 'analysis_failures'
KEY_EXTENSIONS = 'extensions'

if TYPE_CHECKING:
    from saq.analysis.root import RootAnalysis


class RootAnalysisSerializer:
    """Handles JSON serialization and deserialization for RootAnalysis objects."""
    
    
    @staticmethod
    def serialize(root_analysis: "RootAnalysis") -> dict:
        """Converts the RootAnalysis object to a dictionary representation."""
        from saq.analysis.analysis import Analysis
        
        # Get the base analysis JSON representation
        result = {}
        base_json = Analysis.json.fget(root_analysis)
        if base_json:
            result.update(base_json)
        
        # Add RootAnalysis-specific properties
        result.update({
            KEY_ANALYSIS_MODE: root_analysis.analysis_mode,
            KEY_UUID: root_analysis.uuid,
            KEY_TOOL: root_analysis.tool,
            KEY_TOOL_INSTANCE: root_analysis.tool_instance,
            KEY_TYPE: root_analysis.alert_type,
            KEY_DESCRIPTION: root_analysis.description,
            KEY_EVENT_TIME: root_analysis.event_time,
            KEY_ACTION_COUNTERS: root_analysis.action_counters,
            KEY_OBSERVABLE_STORE: root_analysis.analysis_tree_manager.serialize_observable_registry(),
            KEY_NAME: root_analysis.name,
            KEY_REMEDIATION: root_analysis.remediation,
            KEY_STATE: root_analysis.state,
            KEY_LOCATION: root_analysis.location,
            KEY_COMPANY_NAME: root_analysis.company_name,
            KEY_COMPANY_ID: root_analysis.company_id,
            KEY_DELAYED_ANALYSIS_TRACKING: root_analysis.delayed_analysis_tracking,
            KEY_DEPENDECY_TRACKING: root_analysis.analysis_tree_manager.serialize_dependency_tracking(),
            KEY_QUEUE: root_analysis.queue,
            KEY_INSTRUCTIONS: root_analysis.instructions,
            KEY_EXTENSIONS: root_analysis.extensions,
            KEY_ANALYSIS_FAILURES: root_analysis.analysis_failures,
        })

        return result
    
    @staticmethod
    def deserialize(root_analysis: "RootAnalysis", value: dict):
        """Loads the RootAnalysis object from a dictionary representation."""
        assert isinstance(value, dict)
        from saq.analysis.analysis import Analysis
        
        # Load observable store first before we load Observable references
        if KEY_OBSERVABLE_STORE in value:
            root_analysis.analysis_tree_manager.deserialize_observable_registry(value[KEY_OBSERVABLE_STORE])
        
        # Set base analysis properties
        Analysis.json.fset(root_analysis, value)
        
        # Load RootAnalysis-specific properties
        if KEY_ANALYSIS_MODE in value:
            root_analysis._analysis_mode = value[KEY_ANALYSIS_MODE]
            root_analysis._original_analysis_mode = value[KEY_ANALYSIS_MODE]
        if KEY_UUID in value:
            root_analysis.uuid = value[KEY_UUID]
        if KEY_TOOL in value:
            root_analysis._tool = value[KEY_TOOL]
        if KEY_TOOL_INSTANCE in value:
            root_analysis._tool_instance = value[KEY_TOOL_INSTANCE]
        if KEY_TYPE in value:
            root_analysis._alert_type = value[KEY_TYPE]
        if KEY_DESCRIPTION in value:
            root_analysis._description = value[KEY_DESCRIPTION]
        if KEY_EVENT_TIME in value:
            try:
                root_analysis._event_time = parse_event_time(value[KEY_EVENT_TIME])
            except:
                root_analysis._event_time = value[KEY_EVENT_TIME]
        if KEY_ACTION_COUNTERS in value:
            root_analysis._action_counters = value[KEY_ACTION_COUNTERS]
        if KEY_NAME in value:
            root_analysis._name = value[KEY_NAME]
        if KEY_REMEDIATION in value:
            root_analysis._remediation = value[KEY_REMEDIATION]
        if KEY_STATE in value:
            root_analysis._state = value[KEY_STATE]
        if KEY_LOCATION in value:
            root_analysis._location = value[KEY_LOCATION]
        if KEY_COMPANY_NAME in value:
            root_analysis._company_name = value[KEY_COMPANY_NAME]
        if KEY_COMPANY_ID in value:
            root_analysis._company_id = value[KEY_COMPANY_ID]
        if KEY_DELAYED_ANALYSIS_TRACKING in value:
            root_analysis.delayed_analysis_tracking = value[KEY_DELAYED_ANALYSIS_TRACKING]
            for key in root_analysis.delayed_analysis_tracking.keys():
                root_analysis.delayed_analysis_tracking[key] = dateutil.parser.parse(root_analysis.delayed_analysis_tracking[key])
        if KEY_DEPENDECY_TRACKING in value:
            root_analysis.analysis_tree_manager.deserialize_dependency_tracking(value[KEY_DEPENDECY_TRACKING])
        if KEY_QUEUE in value:
            root_analysis._queue = value[KEY_QUEUE]
        if KEY_INSTRUCTIONS in value:
            root_analysis._instructions = value[KEY_INSTRUCTIONS]
        if KEY_EXTENSIONS in value:
            root_analysis._extensions = value[KEY_EXTENSIONS]
        if KEY_ANALYSIS_FAILURES in value:
            root_analysis._analysis_failures = value[KEY_ANALYSIS_FAILURES]
        
        # Set the JSON size for computation in the total_bytes property
        #root_analysis.json_size = sys.getsizeof(value)
    
    @staticmethod
    def save_to_disk(root_analysis: "RootAnalysis") -> bool:
        """Saves the RootAnalysis JSON to disk with encoding and hashing."""
        logging.debug(f"SAVE JSON: {root_analysis} ({type(root_analysis)})")
        
        # Ensure storage directories exist
        if root_analysis.file_manager:
            root_analysis.file_manager.ensure_storage_directories()
        
        # Serialize all analysis details first
        for analysis in root_analysis.all_analysis:
            root_analysis.analysis_tree_manager.save_analysis_details(analysis)
        
        # Now encode and save the main JSON with retry logic
        # Use a temporary file to deal with very large JSON files taking a long time to encode
        temp_path = '{}.tmp'.format(root_analysis.json_path)
        encoded_json = json.dumps(RootAnalysisSerializer.serialize(root_analysis), sort_keys=True, cls=_JSONEncoder)
        
        # Skip writing if already written (no changes)
        with open(temp_path, 'w') as fp:
            #root_analysis.json_size = sys.getsizeof(encoded_json)
            fp.write(encoded_json)
            _track_writes()
            
        shutil.move(temp_path, root_analysis.json_path)
        return True
    
    @staticmethod
    def load_from_disk(root_analysis: "RootAnalysis") -> bool:
        """Loads the RootAnalysis JSON from disk with decoding."""
        assert root_analysis.json_path is not None
        logging.debug("LOAD JSON: called load() on {}".format(root_analysis))
        
        if root_analysis.is_loaded:
            logging.debug("alert {} already loaded".format(root_analysis))
            return True
        
        json_data = None
        with open(root_analysis.json_path, 'r') as fp:
            json_data = fp.read()
        
        parsed_json = json.loads(json_data)
        RootAnalysisSerializer.deserialize(root_analysis, parsed_json)
            
        _track_reads()
        
        # Translate the json into runtime objects
        root_analysis.analysis_tree_manager.load()

        # Load root analysis details
        root_analysis.analysis_tree_manager.load_analysis_details(root_analysis)
        root_analysis.is_loaded = True

        return True
            