import logging
import os
from subprocess import PIPE, Popen
from typing import override
from saq.analysis.analysis import Analysis
from saq.constants import F_FILE, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.observables.file import FileObservable
from saq.util.strings import format_item_list_for_summary


KEY_STDOUT = "stdout"
KEY_STDERR = "stderr"
KEY_IMAGE_FILE = "image_file"
KEY_FILE_LIST = "file_list"

class DMGAnalysis(Analysis):
    """What are the contents of this DMG file?"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_STDOUT: None,
            KEY_STDERR: None,
            KEY_IMAGE_FILE: None,
            KEY_FILE_LIST: [],
        }

    @override
    @property
    def display_name(self) -> str:
        return "DMG Analysis"

    @property
    def stdout(self) -> str:
        return self.details[KEY_STDOUT]
    
    @stdout.setter
    def stdout(self, value: str):
        self.details[KEY_STDOUT] = value

    @property
    def stderr(self) -> str:
        return self.details[KEY_STDERR]
    
    @stderr.setter
    def stderr(self, value: str):
        self.details[KEY_STDERR] = value

    @property
    def image_file(self) -> str:
        return self.details[KEY_IMAGE_FILE]
    
    @image_file.setter
    def image_file(self, value: str):
        self.details[KEY_IMAGE_FILE] = value

    @property
    def file_list(self) -> list[str]:
        return self.details[KEY_FILE_LIST]
    
    @file_list.setter
    def file_list(self, value: list[str]):
        self.details[KEY_FILE_LIST] = value

    def generate_summary(self) -> str:
        if not self.file_list:
            return None

        return f"DMG Analysis: file observabed ({format_item_list_for_summary(self.file_list)})"


class DMGAnalyzer(AnalysisModule):

    def verify_environment(self):
        self.verify_program_exists("dmg2img")
        self.verify_program_exists("7z")

    @property
    def generated_analysis_type(self):
        return DMGAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:
        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.error(f"cannot find local file path {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        # http://newosxbook.com/DMG.html
        # "The first noteable fact about the DMG file format is, that there is no DMG file format."
        if not _file.file_name.lower().endswith(".dmg"):
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)

        # this simply creates the img file in the same folder the file is in
        # replacing .dmg with .img
        process = Popen(["dmg2img", local_file_path], stdout=PIPE, stderr=PIPE)
        analysis.details["stdout"], analysis.details["stderr"] = process.communicate()
        image_file = local_file_path[:-4] + ".img"

        if not os.path.exists(image_file):
            logging.debug(f"failed to create img file {image_file} from {local_file_path}")
            return AnalysisExecutionResult.COMPLETED

        analysis.details["image_file"] = image_file
        file_observable = analysis.add_file_observable(image_file, volatile=True)
        if file_observable:
            file_observable.add_tag("macos")
            file_observable.add_tag("dmg")
            file_observable.redirection = _file

        # get the list of files
        process = Popen(['7z', 'l', image_file], stdout=PIPE, stderr=PIPE, universal_newlines=True)
        _stdout, _stderr = process.communicate()

        # parse the output
        file_listing = False
        for line in _stdout.split("\n"):
            if line.startswith("-------------------"):
                file_listing = not file_listing
                continue

            if file_listing:
                # entries look like this
                # 2021-04-06 23:33:19 D....                            Installer
                # 2021-04-06 23:33:19 .....        16388        20480  Installer/.DS_Store
                if len(line) < 20:
                    continue

                if line[20] == "D": # XXX hardcoded constant based on stdout is not great
                    continue

                # otherwise it should be a file
                analysis.details["file_list"].append(line.strip())

        return AnalysisExecutionResult.COMPLETED
