import binascii
import hashlib
import logging
import os
import re
from saq.analysis.analysis import Analysis
from saq.constants import F_FILE, R_EXTRACTED_FROM, AnalysisExecutionResult
from saq.modules import AnalysisModule
from saq.modules.file_analysis.is_file_type import is_onenote_file
from saq.observables.file import FileObservable
from saq.util.strings import format_item_list_for_summary


class OneNoteFileAnalysis(Analysis):

    KEY_EXTRACTED_FILES = "extracted_files"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { 
            OneNoteFileAnalysis.KEY_EXTRACTED_FILES: []
        }

    @property
    def extracted_files(self):
        if self.details is None:
            return []

        return self.details.get(OneNoteFileAnalysis.KEY_EXTRACTED_FILES, [])

    def generate_summary(self) -> str:
        if not self.details:
            return None

        if not self.extracted_files:
            return None

        return "OneNote File Analysis: extracted files " + format_item_list_for_summary(self.extracted_files)

class OneNoteFileAnalyzer(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return OneNoteFileAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def max_bytes(self):
        return int(self.config.get("max_bytes", 104857600))

    def execute_analysis(self, _file: FileObservable) -> AnalysisExecutionResult:

        local_file_path = _file.full_path
        if not os.path.exists(local_file_path):
            logging.debug(f"local file {local_file_path} does not exist")
            return AnalysisExecutionResult.COMPLETED

        # skip analysis if file is empty
        if os.path.getsize(local_file_path) == 0:
            logging.debug(f"local file {local_file_path} is empty")
            return AnalysisExecutionResult.COMPLETED

        if not is_onenote_file(local_file_path):
            return AnalysisExecutionResult.COMPLETED

        _file.add_tag("onenote")

        analysis = self.create_analysis(_file)
        from saq.onenote import FileDataStoreObject

        # TODO limit size
        with open(local_file_path, "rb") as fp:
            data = fp.read(self.max_bytes)

        for match in re.finditer(
            binascii.unhexlify(b"e716e3bd65261145a4c48d4d0b7a9eac"), data
        ):
            fdso = FileDataStoreObject.parse(data[match.span(0)[0] :])
            payload = fdso.FileData

            target_path = f"{local_file_path}.extracted-{hashlib.sha256(payload).hexdigest()[:6]}"
            with open(target_path, "wb") as fp:
                fp.write(payload)

            file_observable = analysis.add_file_observable(target_path)
            if file_observable:
                file_observable.add_relationship(R_EXTRACTED_FROM, _file)
                #file_observable.add_tag('extracted_from_onenote')
                analysis.extracted_files.append(file_observable.value)

        return AnalysisExecutionResult.COMPLETED