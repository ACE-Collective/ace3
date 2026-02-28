
import pytest

from saq.analysis.root import RootAnalysis
from saq.analysis.summary_detail import CONTENT, FORMAT, HEADER, SummaryDetail
from saq.constants import SUMMARY_DETAIL_FORMAT_MD, SUMMARY_DETAIL_FORMAT_PRE


@pytest.mark.unit
def test_summary_detail_conversion():
    detail = SummaryDetail('test_header', 'test_content', SUMMARY_DETAIL_FORMAT_PRE)
    d = detail.to_dict()
    assert HEADER in d
    assert CONTENT in d
    assert FORMAT in d
    new_detail = SummaryDetail.from_dict(d)
    assert new_detail == detail

@pytest.mark.unit
def test_summary_detail_md_conversion():
    detail = SummaryDetail("test_header", "**bold** and *italic*", SUMMARY_DETAIL_FORMAT_MD)
    d = detail.to_dict()
    assert d[FORMAT] == SUMMARY_DETAIL_FORMAT_MD
    new_detail = SummaryDetail.from_dict(d)
    assert new_detail == detail

@pytest.mark.integration
def test_add_summary_detail():
    root = RootAnalysis()
    root.add_summary_detail('test_header', 'test_content', SUMMARY_DETAIL_FORMAT_PRE)
    assert root.summary_details[0].header == 'test_header'
    assert root.summary_details[0].content == 'test_content'
    assert root.summary_details[0].format == SUMMARY_DETAIL_FORMAT_PRE