
import pytest

from saq.analysis.root import RootAnalysis
from saq.analysis.summary_detail import SummaryDetail
from saq.constants import SUMMARY_DETAIL_FORMAT_PRE


@pytest.mark.unit
def test_summary_detail_conversion():
    # stored in data.json, so the keys are literal
    stored = {"id": "d1", "header": "test_header", "content": "test_content", "format": "pre"}
    detail = SummaryDetail('test_header', 'test_content', SUMMARY_DETAIL_FORMAT_PRE, id="d1")
    assert detail.to_dict() == stored

    restored = SummaryDetail.from_dict(dict(stored))
    assert (restored.id, restored.header, restored.content, restored.format) == \
        ("d1", "test_header", "test_content", "pre")
    assert restored == detail
    assert restored != SummaryDetail('test_header', 'test_content', SUMMARY_DETAIL_FORMAT_PRE, id="d2")

@pytest.mark.integration
def test_add_summary_detail():
    root = RootAnalysis()
    root.add_summary_detail('test_header', 'test_content', SUMMARY_DETAIL_FORMAT_PRE)
    assert root.summary_details[0].header == 'test_header'
    assert root.summary_details[0].content == 'test_content'
    assert root.summary_details[0].format == SUMMARY_DETAIL_FORMAT_PRE