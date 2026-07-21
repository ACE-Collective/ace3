from unittest.mock import Mock, patch

import pytest
from flask import url_for

from saq.constants import (
    ANALYSIS_MODE_CORRELATION,
    ANALYSIS_MODE_DISPOSITIONED,
    DIRECTIVE_CLICKER_DETECTION,
    F_FQDN,
    F_IP,
    F_URL,
)
from saq.analysis.root import RootAnalysis
from saq.gui.alert import GUIAlert

ROUTE = "app.analysis.views.edit.observable_action.clicker"


@pytest.fixture
def mock_alert():
    alert = Mock(spec=GUIAlert)
    alert.uuid = "test-alert-uuid"
    alert.load = Mock(return_value=True)
    # a real RootAnalysis (not a Mock) so analysis_mode and state round-trip honestly -- a Mock
    # silently accepts a mode set on the wrong object, which is how the dispositioned-requeue bug hid
    alert.root_analysis = RootAnalysis(uuid="test-root-uuid", analysis_mode=ANALYSIS_MODE_DISPOSITIONED)
    alert.root_analysis.get_observable = Mock()
    return alert


@pytest.mark.integration
class TestCheckForClickers:
    @patch(f"{ROUTE}.get_current_alert")
    def test_no_alert(self, mock_get_alert, web_client):
        mock_get_alert.return_value = None
        r = web_client.post(url_for("analysis.observable_action_check_for_clickers"),
                            data={"observable_uuid": "x", "alert_uuid": "y"})
        assert r.status_code == 404

    @patch(f"{ROUTE}.release_lock")
    @patch(f"{ROUTE}.acquire_lock", return_value=True)
    @patch(f"{ROUTE}.get_current_alert")
    def test_wrong_observable_type(self, mock_get_alert, _lock, _unlock, web_client, mock_alert):
        obs = Mock()
        obs.type = F_IP
        mock_alert.root_analysis.get_observable.return_value = obs
        mock_get_alert.return_value = mock_alert
        r = web_client.post(url_for("analysis.observable_action_check_for_clickers"),
                            data={"observable_uuid": "x", "alert_uuid": "y"})
        assert r.status_code == 400

    @patch(f"{ROUTE}.add_workload")
    @patch(f"{ROUTE}.release_lock")
    @patch(f"{ROUTE}.acquire_lock", return_value=True)
    @patch(f"{ROUTE}.get_current_alert")
    def test_adds_directive_and_requeues(self, mock_get_alert, _lock, _unlock, mock_add_workload,
                                         web_client, mock_alert):
        obs = Mock()
        obs.type = F_URL
        obs.all_analysis = []
        obs._analysis = {}
        mock_alert.root_analysis.get_observable.return_value = obs
        mock_get_alert.return_value = mock_alert

        r = web_client.post(url_for("analysis.observable_action_check_for_clickers"),
                            data={"observable_uuid": "x", "alert_uuid": "y"})

        assert r.status_code == 200
        obs.add_directive.assert_called_once_with(DIRECTIVE_CLICKER_DETECTION)
        mock_alert.sync.assert_called_once()
        mock_add_workload.assert_called_once()
        # the requeue mode must be set on root_analysis (what add_workload reads), not the Alert
        # ORM column -- otherwise a dispositioned alert re-queues in 'dispositioned' mode (no modules)
        assert mock_alert.root_analysis.analysis_mode == ANALYSIS_MODE_CORRELATION

    @patch(f"{ROUTE}.add_workload")
    @patch(f"{ROUTE}.release_lock")
    @patch(f"{ROUTE}.acquire_lock", return_value=True)
    @patch(f"{ROUTE}.get_current_alert")
    def test_removes_prior_clicker_analysis_to_force_rerun(self, mock_get_alert, _lock, _unlock,
                                                           _add_workload, web_client, mock_alert):
        """A repeat run must drop prior clicker-provider analyses so the searches re-run; other
        analyses on the observable are left intact."""
        class FakeClickerAnalysis:
            pass

        class OtherAnalysis:
            pass

        prior = FakeClickerAnalysis()
        prior.module_path = "fake:FakeClickerAnalysis"
        other = OtherAnalysis()
        other.module_path = "other:OtherAnalysis"

        obs = Mock()
        obs.type = F_URL
        obs.all_analysis = [prior, other]
        mock_alert.root_analysis.get_observable.return_value = obs
        mock_get_alert.return_value = mock_alert

        with patch(f"{ROUTE}.REGISTERED_CLICKER_PROVIDERS", [FakeClickerAnalysis]):
            r = web_client.post(url_for("analysis.observable_action_check_for_clickers"),
                                data={"observable_uuid": "x", "alert_uuid": "y"})

        assert r.status_code == 200
        # prior clicker analysis is deleted (forces re-run); unrelated analysis is left intact
        obs.delete_analysis.assert_called_once_with(prior)


@pytest.mark.integration
class TestOpenSplunkClickerSearch:
    @patch(f"{ROUTE}.get_current_alert")
    def test_no_alert(self, mock_get_alert, web_client):
        mock_get_alert.return_value = None
        r = web_client.post(url_for("analysis.observable_action_open_clicker_search_splunk"),
                            data={"observable_uuid": "x", "alert_uuid": "y"})
        assert r.status_code == 404

    @patch(f"{ROUTE}.build_splunk_clicker_search_urls",
           return_value=[{"name": "safelinks", "url": "https://splunk.example/search?q=a"},
                         {"name": "proxy", "url": "https://splunk.example/search?q=b"}])
    @patch(f"{ROUTE}.get_current_alert")
    def test_returns_urls(self, mock_get_alert, _build, web_client, mock_alert):
        obs = Mock()
        obs.type = F_FQDN
        mock_alert.root_analysis.get_observable.return_value = obs
        mock_get_alert.return_value = mock_alert

        r = web_client.post(url_for("analysis.observable_action_open_clicker_search_splunk"),
                            data={"observable_uuid": "x", "alert_uuid": "y"})
        assert r.status_code == 200
        assert [u["name"] for u in r.json["urls"]] == ["safelinks", "proxy"]

    @patch(f"{ROUTE}.build_splunk_clicker_search_urls", return_value=[])
    @patch(f"{ROUTE}.get_current_alert")
    def test_no_search_configured(self, mock_get_alert, _build, web_client, mock_alert):
        obs = Mock()
        obs.type = F_URL
        mock_alert.root_analysis.get_observable.return_value = obs
        mock_get_alert.return_value = mock_alert

        r = web_client.post(url_for("analysis.observable_action_open_clicker_search_splunk"),
                            data={"observable_uuid": "x", "alert_uuid": "y"})
        assert r.status_code == 200
        assert "url" not in r.json
        assert "No Splunk clicker search" in r.json["message"]
