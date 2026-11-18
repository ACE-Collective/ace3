import pytest

from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.analysis.pivot_link import PivotLink
from saq.analysis.root import RootAnalysis
from saq.constants import F_TEST


@pytest.mark.unit
def test_pivot_links():
    # stored in data.json, so the keys are literal
    link = PivotLink("test1", "test2", "test3")
    assert link.to_dict() == {"url": "test1", "icon": "test2", "text": "test3"}

    restored = PivotLink.from_dict({"url": "test1", "icon": "test2", "text": "test3"})
    assert (restored.url, restored.icon, restored.text) == ("test1", "test2", "test3")

@pytest.mark.unit
def test_root_analysis_pivot_link_serialization(tmpdir):
    root = RootAnalysis(storage_dir=str(tmpdir))
    root.add_pivot_link("test1", "test2", "test3")
    root.save()

    root = RootAnalysis(storage_dir=str(tmpdir))
    root.load()
    assert root.pivot_links[0] == PivotLink("test1", "test2", "test3")

@pytest.mark.unit
def test_analysis_pivot_link_serialization(tmpdir):

    root = RootAnalysis(storage_dir=str(tmpdir))
    observable = root.add_observable_by_spec(F_TEST, "test")
    assert isinstance(observable, Observable)
    analysis = Analysis()
    analysis.add_pivot_link("test1", "test2", "test3")
    observable.add_analysis(analysis)
    root.save()

    root = RootAnalysis(storage_dir=str(tmpdir))
    root.load()
    observable = root.get_observables_by_type(F_TEST)[0]
    analysis = observable.all_analysis[0]
    assert analysis.pivot_links[0] == PivotLink("test1", "test2", "test3")