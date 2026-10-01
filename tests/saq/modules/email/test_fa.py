import pytest

from saq.analysis.analysis import Analysis
from saq.constants import F_TEST
from saq.modules.email.fa import _tree_has_tag
from tests.saq.helpers import create_root_analysis


class ChildAnalysis(Analysis):
    pass


def _build_tree():
    root = create_root_analysis()
    target = root.add_observable_by_spec(F_TEST, "attachment")
    analysis = ChildAnalysis()
    target.add_analysis(analysis)
    child = analysis.add_observable_by_spec(F_TEST, "embedded")
    return target, child


@pytest.mark.unit
def test_tree_has_tag_below_target():
    target, child = _build_tree()
    child.add_tag("macro")
    assert _tree_has_tag(target, "macro")


@pytest.mark.unit
def test_tree_has_tag_on_target():
    target, _ = _build_tree()
    target.add_tag("macro")
    assert _tree_has_tag(target, "macro")


@pytest.mark.unit
def test_tree_has_tag_missing():
    target, child = _build_tree()
    child.add_tag("something_else")
    assert not _tree_has_tag(target, "macro")
