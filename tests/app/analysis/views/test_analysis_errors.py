import pytest
from flask import url_for

from app.analysis.views.index import build_analysis_failure_map
from saq.analysis.analysis import Analysis
from saq.analysis.module_path import MODULE_PATH
from saq.analysis.root import RootAnalysis
from saq.constants import F_TEST
from saq.database.util.alert import ALERT
from saq.modules.test import BasicTestAnalysis, LowPriorityAnalysis

MESSAGE = "lookup <b>timed</b> out"
ESCAPED = "lookup &lt;b&gt;timed&lt;/b&gt; out"


class _NoResultAnalysis(Analysis):
    """No summary and no observables: without an error the tree does not show it."""


@pytest.mark.integration
def test_alert_page_shows_a_failed_analysis_that_produced_nothing(web_client, root_analysis):
    observable = root_analysis.add_observable_by_spec(F_TEST, "test")
    observable.add_analysis(_NoResultAnalysis()).error = MESSAGE
    root_analysis.save()
    ALERT(root_analysis)

    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})

    assert result.status_code == 200
    # without the error it has no summary and no observables, and is not shown at all
    assert "_NoResultAnalysis" in result.text
    assert "The analysis module failed" in result.text
    assert ESCAPED in result.text
    assert MESSAGE not in result.text


@pytest.mark.integration
def test_alert_page_shows_a_module_that_failed_without_an_analysis(web_client, root_analysis):
    observable = root_analysis.add_observable_by_spec(F_TEST, "test")
    root_analysis.set_analysis_failed(MODULE_PATH(BasicTestAnalysis), F_TEST, "test", error_message=MESSAGE)
    root_analysis.save()
    ALERT(root_analysis)

    result = web_client.get(url_for("analysis.index"), query_string={"direct": root_analysis.uuid})

    assert result.status_code == 200
    assert "BasicTestAnalysis" in result.text
    assert ESCAPED in result.text
    assert MESSAGE not in result.text


@pytest.mark.integration
def test_analysis_page_shows_why_the_module_failed(web_client, root_analysis):
    observable = root_analysis.add_observable_by_spec(F_TEST, "test")
    analysis = observable.add_analysis(BasicTestAnalysis())
    analysis.error = MESSAGE
    root_analysis.save()
    ALERT(root_analysis)

    result = web_client.get(url_for("analysis.index"), query_string={
        "direct": root_analysis.uuid, "observable_uuid": observable.uuid, "module_path": analysis.module_path})

    assert result.status_code == 200
    assert f"BasicTestAnalysis failed:</b>" in result.text
    assert ESCAPED in result.text


@pytest.mark.unit
def test_failure_map_leaves_out_failures_shown_on_an_analysis():
    root = RootAnalysis()
    failed = root.add_observable_by_spec(F_TEST, "failed")
    analyzed = root.add_observable_by_spec(F_TEST, "analyzed")
    analyzed.add_analysis(BasicTestAnalysis()).error = "shown on the analysis"
    root.set_analysis_failed(MODULE_PATH(BasicTestAnalysis), F_TEST, "failed", error_message="died")
    root.set_analysis_failed(MODULE_PATH(BasicTestAnalysis), F_TEST, "analyzed", error_message="died")
    root.set_analysis_failed(MODULE_PATH(LowPriorityAnalysis, instance="x"), F_TEST, "failed")

    assert build_analysis_failure_map(root) == {
        failed.uuid: [("BasicTestAnalysis", "died"), ("LowPriorityAnalysis:x", "the analysis module failed")],
    }
