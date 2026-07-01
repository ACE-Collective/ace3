import logging
import os
from subprocess import DEVNULL, Popen
from typing import Type, override
from pydantic import Field
from saq.analysis.analysis import Analysis
from saq.signatures import OLE_EXTRACTED_SUSPECT_FILE
from saq.constants import AnalysisExecutionResult, F_FILE
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.file_analysis.is_file_type import is_javascript_file
from saq.observables.file import FileObservable
from saq.util.strings import format_item_list_for_summary


KEY_SUSPECT_FILES = "suspect_files"

class ExtractedOLEAnalysis(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_SUSPECT_FILES: []
        }

    @override
    @property
    def display_name(self):
        return "Extracted OLE Analysis"

    @property
    def suspect_files(self):
        return self.details[KEY_SUSPECT_FILES]

    @suspect_files.setter
    def suspect_files(self, value):
        self.details[KEY_SUSPECT_FILES] = value

    def generate_summary(self):
        if not self.suspect_files:
            return None

        return f"{self.display_name}: identified ({format_item_list_for_summary(self.suspect_files)}) as suspect files"

class ExtractedOLEAnalyzerConfig(AnalysisModuleConfig):
    suspect_file_type: str = Field(..., description="Comma separated list of things to search for in the output of the file command.")
    suspect_file_ext: str = Field(..., description="Comma separated list of extracted file extensions that would be considered suspect.")

class ExtractedOLEAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return ExtractedOLEAnalyzerConfig

    @property
    def suspect_file_type(self):
        return map(lambda x: x.strip(), self.config.suspect_file_type.split(','))

    @property
    def suspect_file_ext(self):
        return map(lambda x: x.strip(), self.config.suspect_file_ext.split(','))

    @property
    def generated_analysis_type(self):
        return ExtractedOLEAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE
    
    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        from saq.modules.file_analysis.file_type import FileTypeAnalysis
        from saq.modules.file_analysis.officeparser3 import OfficeParserAnalysis3

        # gather all the requirements for all the things we want to check
        file_type_analysis = self.wait_for_analysis(_file, FileTypeAnalysis)
        if not file_type_analysis:
            return AnalysisExecutionResult.COMPLETED

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error("cannot find local file path for {}".format(_file))
            return AnalysisExecutionResult.COMPLETED

        # is this _file an output of the OfficeParserAnalysis?
        if any([isinstance(a, OfficeParserAnalysis3) for a in self.get_root().iterate_all_references(_file)]):
            analysis = self.create_analysis(_file)
            assert isinstance(analysis, ExtractedOLEAnalysis)

            # is this file not a type of file we expect to see here?
            # we have a list of things we look for here in the configuration
            suspect = False
            for suspect_file_type in self.suspect_file_type:
                if suspect_file_type.lower().strip() in file_type_analysis.file_type.lower():
                    _file.add_detection_point("OLE attachment has suspect file type {}".format(suspect_file_type), signature_uuid=OLE_EXTRACTED_SUSPECT_FILE.uuid)
                    suspect = True
                    break

            if not suspect:
                for suspect_file_ext in self.suspect_file_ext:
                    if _file.file_path.lower().endswith('.{}'.format(suspect_file_ext)):
                        _file.add_detection_point("OLE attachment has suspect file ext {}".format(suspect_file_ext), signature_uuid=OLE_EXTRACTED_SUSPECT_FILE.uuid)
                        suspect = True
                        break

            # one last check -- see if this file compiles as javascript
            # the file command may return plain text for some js files without extension
            if not suspect:
                if is_javascript_file(local_file_path):
                    _file.add_detection_point("OLE attachment {} is a javascript file".format(_file), signature_uuid=OLE_EXTRACTED_SUSPECT_FILE.uuid)
                    suspect = True

            if suspect:
                logging.info("found suspect ole attachment {} in {}".format(suspect_file_type, _file))
                analysis.suspect_files.append(_file.display_value)
                _file.add_tag('suspect_ole_attachment')

            return AnalysisExecutionResult.COMPLETED

        return AnalysisExecutionResult.COMPLETED