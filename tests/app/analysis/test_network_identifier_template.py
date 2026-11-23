import pytest

from saq.modules.asset.network_identifier import NetworkIdentifierAnalysis, NetworkIdentifierAnalysisPresenter


def _render(app, analysis: NetworkIdentifierAnalysis) -> str:
    presenter = NetworkIdentifierAnalysisPresenter(analysis)
    template = app.jinja_env.get_template(presenter.template_path)
    return template.render(analysis=analysis, analysis_presenter=presenter)


@pytest.mark.integration
def test_each_identified_network_is_listed(app):
    analysis = NetworkIdentifierAnalysis()
    analysis.identified_networks = ["corporate", "<b>datacenter</b>"]
    html = _render(app, analysis)

    assert html.count("<li>") == 2
    assert "<li>corporate</li>" in html
    # network names come from an analyst-maintained CSV and are escaped like anything else
    assert "<li>&lt;b&gt;datacenter&lt;/b&gt;</li>" in html
    assert "identified_networks" not in html


@pytest.mark.integration
def test_no_networks_lists_nothing(app):
    html = _render(app, NetworkIdentifierAnalysis())

    assert "<li>" not in html
