import pytest

from saq.analysis import RootAnalysis
from saq.analysis.presenter import create_observable_presenter
from saq.analysis.presenter.observable_presenter import ObservablePresenter
from saq.constants import F_EMAIL_FIRST_HOP_IP, F_IP, F_URL
from saq.observables.network.ip import IPObservablePresenter


@pytest.mark.unit
def test_ip_observable_uses_ip_presenter():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, "192.168.1.1")
    presenter = create_observable_presenter(o)
    assert isinstance(presenter, IPObservablePresenter)
    assert presenter.template_path == "analysis/ip_observable.html"


@pytest.mark.unit
def test_ip_subclass_inherits_ip_presenter():
    # EmailFirstHopIPObservable extends IPObservable without registering its own presenter;
    # the MRO walk must resolve it to IPObservablePresenter so it renders the VirusTotal badge
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_EMAIL_FIRST_HOP_IP, "192.168.1.1")
    presenter = create_observable_presenter(o)
    assert isinstance(presenter, IPObservablePresenter)
    assert presenter.template_path == "analysis/ip_observable.html"


@pytest.mark.unit
def test_unregistered_observable_uses_default_presenter():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_URL, "https://example.com/")
    presenter = create_observable_presenter(o)
    assert type(presenter) is ObservablePresenter
    assert presenter.template_path == "analysis/default_observable.html"
