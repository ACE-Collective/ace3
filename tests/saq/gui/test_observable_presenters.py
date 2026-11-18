import pytest

from saq.analysis import RootAnalysis
from saq.analysis.presenter.observable_presenter import ObservablePresenter, create_observable_presenter
from saq.constants import (
    ACTION_CHECK_FOR_CLICKERS,
    ACTION_COLLECT_FILE,
    ACTION_FILE_DOWNLOAD_AS_ZIP,
    ACTION_FILE_RENDER,
    ACTION_FILE_VIEW_AS_HEX,
    ACTION_FILE_VIEW_AS_TEXT,
    ACTION_OPEN_CLICKER_SEARCH_SPLUNK,
    ACTION_URL_CRAWL,
    F_EMAIL_CONVERSATION,
    F_EMAIL_FIRST_HOP_IP,
    F_FILE_LOCATION,
    F_FQDN,
    F_HOSTNAME,
    F_INDICATOR,
    F_IP,
    F_IPV4,
    F_SHA256,
    F_URL,
    F_USER,
)
from saq.gui.observable_presenters import (
    EmailConversationObservablePresenter,
    FileLocationObservablePresenter,
    FileObservablePresenter,
    FQDNObservablePresenter,
    HostnameObservablePresenter,
    IndicatorObservablePresenter,
    IPObservablePresenter,
    IPv4ObservablePresenter,
    SHA256ObservablePresenter,
    UserObservablePresenter,
)


def _action_names(observable) -> list[str]:
    # detection_status and is_interesting given, so the presenter asks no database
    presenter = create_observable_presenter(observable, detection_status=False, is_interesting=False)
    # only core's: an installed integration registers its own actions on the same types from its gui_blueprint,
    # which the GUI app (built by earlier tests in this process) or a test of the integration has imported
    return [action.name for action in presenter.available_actions
            if action.name and type(action).__module__.startswith("saq.")]


@pytest.mark.unit
def test_ip_observable_uses_ip_presenter():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_IP, "192.168.1.1")
    presenter = create_observable_presenter(o)
    assert isinstance(presenter, IPObservablePresenter)
    assert presenter.template_path == "analysis/ip_observable.html"


@pytest.mark.unit
@pytest.mark.parametrize("observable_type, value, presenter_class, template_path", [
    (F_USER, "jdoe", UserObservablePresenter, "analysis/user_observable.html"),
    (F_EMAIL_CONVERSATION, "a@example.com|b@example.com", EmailConversationObservablePresenter,
     "analysis/email_conversation_observable.html"),
    (F_HOSTNAME, "workstation1", HostnameObservablePresenter, "analysis/hostname_observable.html"),
    # its template hides the value when gui.hide_intel is set
    (F_INDICATOR, "5f0c8e2b9d1a4c3e7b6a5d4c", IndicatorObservablePresenter, "analysis/indicator_observable.html"),
    (F_FQDN, "example.com", FQDNObservablePresenter, "analysis/fqdn_observable.html"),
    (F_IP, "192.168.1.1", IPObservablePresenter, "analysis/ip_observable.html"),
    (F_IPV4, "192.168.1.1", IPv4ObservablePresenter, "analysis/ipv4_observable.html"),
    (F_SHA256, "a" * 64, SHA256ObservablePresenter, "analysis/sha256_observable.html"),
    (F_FILE_LOCATION, "host@/tmp/sample.txt", FileLocationObservablePresenter,
     "analysis/file_location_observable.html"),
])
def test_core_presenters(observable_type, value, presenter_class, template_path):
    o = RootAnalysis().add_observable_by_spec(observable_type, value)
    presenter = create_observable_presenter(o)
    assert type(presenter) is presenter_class
    assert presenter.template_path == template_path


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


@pytest.mark.unit
def test_url_actions():
    root = RootAnalysis()
    names = _action_names(root.add_observable_by_spec(F_URL, "https://example.com/"))
    assert names[-3:] == [ACTION_URL_CRAWL, ACTION_CHECK_FOR_CLICKERS, ACTION_OPEN_CLICKER_SEARCH_SPLUNK]


@pytest.mark.unit
def test_fqdn_actions():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_FQDN, "example.com")
    assert isinstance(create_observable_presenter(o), FQDNObservablePresenter)
    assert _action_names(o)[-2:] == [ACTION_CHECK_FOR_CLICKERS, ACTION_OPEN_CLICKER_SEARCH_SPLUNK]


@pytest.mark.unit
def test_file_actions(tmp_path):
    root = RootAnalysis(storage_dir=str(tmp_path))
    root.initialize_storage()
    path = tmp_path / "sample.txt"
    path.write_text("hello")
    o = root.add_file_observable(str(path))
    presenter = create_observable_presenter(o)
    assert type(presenter) is FileObservablePresenter
    assert presenter.template_path == "analysis/file_observable.html"
    assert _action_names(o)[:4] == [ACTION_FILE_DOWNLOAD_AS_ZIP, ACTION_FILE_VIEW_AS_HEX, ACTION_FILE_VIEW_AS_TEXT,
                                    ACTION_FILE_RENDER]


@pytest.mark.unit
def test_file_location_actions():
    root = RootAnalysis()
    o = root.add_observable_by_spec(F_FILE_LOCATION, "host@/tmp/sample.txt")
    assert isinstance(create_observable_presenter(o), FileLocationObservablePresenter)
    assert _action_names(o)[0] == ACTION_COLLECT_FILE
