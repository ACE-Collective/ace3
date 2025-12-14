import json
import logging
import os
from typing import TYPE_CHECKING
import uuid

from saq.error.reporting import report_exception

if TYPE_CHECKING:
    from saq.analysis.analysis import Analysis

from saq.analysis.file_manager.file_manager_interface import FileManagerInterface
from saq.analysis.io_tracking import _track_reads, _track_writes
from saq.environment import get_base_dir
from saq.json_encoding import _JSONEncoder
from saq.util import abs_path

class AnalysisDetailsPersistenceManager:
    """Responsible for managing the persistence of analysis details."""
    
    def __init__(self, file_manager: FileManagerInterface):
        """Initialize the persistence manager for the details of the given Analysis object."""
        self.file_manager = file_manager
    
    def save(self, analysis: "Analysis") -> bool:
        """Saves the current results of the analysis to disk."""

        if not analysis.details_modified:
            logging.debug(f"{analysis} was not modified so not saving")
            return False

        # the only thing we actually save is the self.details object
        # which much be serializable to JSON

        # do we not have anything to save?
        #if not self.external_details_loaded and self._details is None:
            #logging.debug(f"called save() on analysis {self.analysis} but nothing to save")
            #return

        #if self.file_manager.storage_dir is None:
            #raise RuntimeError("storage_dir is None for {} in {}".format(self.analysis, self.analysis.root))

        # generate a summary before we go to disk
        # this gets stored in the main json data structure
        if not analysis.delayed:
            try:
                analysis.summary = analysis.generate_summary()
            except Exception as e:
                analysis.summary = f"Failed to generate summary for {analysis}: {e}"

        # have we figured out where we are saving the data to?
        target_name = type(analysis).__name__
        if analysis.instance is not None:
            target_name += '_' + analysis.instance

        if analysis.external_details_path is None:
            analysis.external_details_path = '{}_{}.json'.format(target_name, str(uuid.uuid4()))

        # make sure the containing directory exists
        if not os.path.exists(os.path.join(get_base_dir(), self.file_manager.storage_dir)):
            os.makedirs(os.path.join(get_base_dir(), self.file_manager.storage_dir))

        # analysis details go into a hidden directory
        if not os.path.exists(os.path.join(get_base_dir(), self.file_manager.storage_dir, '.ace')):
            os.makedirs(os.path.join(get_base_dir(), self.file_manager.storage_dir, '.ace'))

        json_data = json.dumps(analysis.details, sort_keys=True, cls=_JSONEncoder)

        # save the details
        logging.debug("SAVE: saving external details for {} to {}".format(analysis, analysis.external_details_path))
        with open(os.path.join(get_base_dir(), self.file_manager.storage_dir, '.ace', analysis.external_details_path), 'w') as fp:
            fp.write(json_data)
            _track_writes()

        analysis.details_size = os.path.getsize(os.path.join(get_base_dir(), self.file_manager.storage_dir, '.ace', analysis.external_details_path))
        return True

    def flush(self, analysis: "Analysis"):
        """Calls save() and then clears the details property.  It must be load()ed again."""
        self.save(analysis)
        analysis.details = {}
        analysis.details_modified = False

    # XXX: when would I ever want to use this?
    def reset(self, analysis: "Analysis"):
        """Deletes the current analysis output if it exists."""
        logging.debug("called reset() on {}".format(analysis))
        if analysis.external_details_path is not None:
            full_path = abs_path(os.path.join(self.file_manager.storage_dir, '.ace', analysis.external_details_path))
            if os.path.exists(full_path):
                logging.debug("removing external details file {}".format(full_path))
                os.remove(full_path)
            else:
                logging.warning("external details path {} does not exist".format(full_path))

        analysis.details = {}
        analysis.external_details_path = None
        analysis.details_size = False
        analysis.details_modified = True

    # XXX: when would I ever want to use this?
    def discard_details(self, analysis: "Analysis"):
        """Simply discards the details of this analysis, not saving any changes."""
        analysis.details = {}
        analysis.details_modified = True

    def load_details(self, analysis: "Analysis") -> bool:
        """Loads the details referenced by this object as a dict or None if the operation failed."""

        if analysis.external_details_path is None:
            logging.error("external_details_path is None for {}".format(analysis))
            return False

        full_file_path = os.path.join(get_base_dir(), self.file_manager.storage_dir, '.ace', analysis.external_details_path)

        if not os.path.exists(full_file_path):
            logging.debug(f"missing file {full_file_path}")
            return False

        json_file_size = os.path.getsize(full_file_path)
        if json_file_size == 0:
            logging.debug(f"analysis details {full_file_path} has no content")
            return False

        if analysis.details_size is not None and analysis.details_size != json_file_size:
            logging.warning(f"analysis details {full_file_path} has size {json_file_size} but expected {analysis.details_size}")

        try:
            with open(full_file_path, 'r') as fp:
                analysis.details = json.load(fp)
                # TODO: right now the assumption is made that if the details are loaded from disk, they are modified
                analysis.details_modified = True

            _track_reads()

            logging.debug(f"LOAD: loaded external details from {full_file_path} (value type {type(analysis.details)})")
            return True

        except Exception as e:
            # this can happen now if the alert is still analyzing
            # since we are flushing as we go and they can be loaded at any time
            logging.warning(f"unable to load json from {full_file_path}: {e}")
            report_exception()
            return False
