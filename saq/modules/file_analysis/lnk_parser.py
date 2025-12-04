from datetime import datetime
import json
import logging
import ntpath
import os
from typing import Optional, override
from saq.analysis.analysis import Analysis
from saq.constants import F_FILE, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_lnk_file
from saq.observables.file import FileObservable
from saq.error import report_exception

import LnkParse3
import warnings
warnings.filterwarnings("ignore", module="LnkParse3")

KEY_ERROR = "error"
KEY_INFO = "info"

def get_target_path(info: dict) -> Optional[str]:
    items = info.get("target", {}).get("items", [])
    if not items:
        return None

    target_path = []

    for item in items:
        if not isinstance(item, dict):
            logging.warning(f"unexpected item type {type(item)} in target path {items}")
            continue

        item_class = item.get("class")
        if not item_class:
            logging.debug(f"no item class for {item} in target path {items}")
            continue

        if item_class == "Volume Item":
            volume_name = item.get("data")
            if not volume_name:
                logging.debug(f"no volume name for {item} in target path {items}")
                continue

            target_path.insert(0, volume_name)
            continue

        if item_class == "File entry":
            item_name = item.get("primary_name")
            if not item_name:
                logging.debug(f"no item name for {item} in target path {items}")
                continue

            target_path.append(item_name)
            continue

    if not target_path:
        return None

    return ntpath.join(*target_path)

class LnkParseAnalysis(Analysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_ERROR: None,
            KEY_INFO: {},
        }

    @override
    @property
    def display_name(self) -> str:
        return "LnkParse Analysis"

    @property
    def error(self):
        return self.details[KEY_ERROR]

    @error.setter
    def error(self, value):
        self.details[KEY_ERROR] = value

    @property
    def info(self):
        return self.details[KEY_INFO]

    @info.setter
    def info(self, value):
        self.details[KEY_INFO] = value

    @property
    def command_line_arguments(self) -> Optional[str]:
        if not self.info:
            return None

        return self.info.get("data", {}).get("command_line_arguments")

    @property
    def icon_location(self) -> Optional[str]:
        if not self.info:
            return None

        return self.info.get("data", {}).get("icon_location")

    @property
    def working_directory(self) -> Optional[str]:
        if not self.info:
            return None

        return self.info.get("data", {}).get("working_directory")

    @property
    def target_path(self) -> Optional[str]:
        if not self.info:
            return None

        return get_target_path(self.info)

    def generate_summary(self) -> str:
        if self.error:
            return f"{self.display_name}: {self.error}"

        parts = []
        if self.target_path:
            parts.append(f"target path: ({self.target_path})")
        if self.command_line_arguments:
            parts.append(f"command line arguments: ({self.command_line_arguments})")
        if self.icon_location:
            parts.append(f"icon location: ({self.icon_location})")
        if self.working_directory:
            parts.append(f"working directory: ({self.working_directory})")

        if not parts:
            return None

        return f"{self.display_name}: {', '.join(parts)}"


class LnkParseAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_program_exists('lnkparse')

    @property
    def generated_analysis_type(self):
        return LnkParseAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error(f"cannot find local file path {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        if not is_lnk_file(local_file_path):
            logging.debug(f'{local_file_path} is not a .lnk file')
            return AnalysisExecutionResult.COMPLETED

        _file.add_tag("lnk")

        analysis = self.create_analysis(_file)
        target_file = f'{local_file_path}.lnkparser.json'

        try:
            # Parse the lnk file
            with open(local_file_path, 'rb') as fp:
                lnk = LnkParse3.lnk_file(fp)

            analysis.info = lnk.get_json(get_all=True)
            analysis.command = lnk.lnk_command

            def _datetime_to_str(obj):
                if isinstance(obj, datetime):
                    return obj.replace(microsecond=0).isoformat()
                return obj

            with open(target_file, 'w') as fp:
                json.dump(
                    analysis.info,
                    fp,
                    indent=4,
                    #separators=(",", ": "),
                    default=_datetime_to_str,
                    sort_keys=True,
                )

            analysis.add_file_observable(target_file)
            
        except Exception as e:
            report_exception()
            analysis.error = str(e)
            logging.info(f'LnkParse failed for {local_file_path}')
        
        return AnalysisExecutionResult.COMPLETED