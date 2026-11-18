import base64

import pytest

from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_ONENOTE_EXTRACTION, AnalysisExecutionResult

from saq.modules.file_analysis import OneNoteFileAnalyzer, OneNoteFileAnalysis
from saq.modules.adapter import AnalysisModuleAdapter
from tests.saq.helpers import create_root_analysis

@pytest.mark.unit
def test_onenote_embedded_files_are_extracted(datadir, test_context):
    root = create_root_analysis(analysis_mode='test_single')
    root.initialize_storage()

    target_path = root.create_file_path("sample.one")
    with open(str(datadir / "sample.one.b64"), "r") as fp_in:
        with open(target_path, "wb") as fp_out:
            fp_out.write(base64.b64decode(fp_in.read()))

    observable = root.add_file_observable(target_path)
    
    analyzer = AnalysisModuleAdapter(OneNoteFileAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_ONENOTE_EXTRACTION)))
    analyzer.root = root
    
    result = analyzer.execute_analysis(observable)
    assert result == AnalysisExecutionResult.COMPLETED
    analysis = observable.get_and_load_analysis(OneNoteFileAnalysis)
    assert isinstance(analysis, OneNoteFileAnalysis)

    assert len(analysis.extracted_files) == 3
