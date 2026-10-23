import logging

import pytest

from saq.analysis.root import load_root
from saq.constants import F_FQDN
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.url.idna import IDNAAnalysis
from saq.util.uuid import get_storage_dir


def _analyze(root_analysis, fqdn):
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_FQDN, fqdn)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("idna_analyzer", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    observable = root_analysis.get_observable(observable.uuid)
    return observable, observable.get_and_load_analysis(IDNAAnalysis)


@pytest.mark.parametrize("fqdn, idna, unicode, added, display_type", [
    # a homograph of apple.com in cyrillic adds its punycode form
    ("аррӏе.com", "xn--80ak6aa92e.com", "аррӏе.com", "xn--80ak6aa92e.com", "IDNA Domain"),
    # and punycode adds the unicode form an analyst can read
    ("xn--80ak6aa92e.com", "xn--80ak6aa92e.com", "аррӏе.com", "аррӏе.com", "Unicode Domain"),
    ("xn--mnchen-3ya.de", "xn--mnchen-3ya.de", "münchen.de", "münchen.de", "Unicode Domain"),
])
@pytest.mark.integration
def test_internationalized_domain(root_analysis, fqdn, idna, unicode, added, display_type):
    _, analysis = _analyze(root_analysis, fqdn)

    assert isinstance(analysis, IDNAAnalysis)
    assert analysis.original == fqdn
    assert analysis.idna == idna
    assert analysis.unicode == unicode
    assert analysis.generate_summary() == f"IDNA: idna={idna}, unicode={unicode}"

    observables = analysis.get_observables_by_type(F_FQDN)
    assert [o.value for o in observables] == [added]
    assert observables[0].display_type == f"{display_type} (fqdn)"
    # the added form is not converted back again
    assert not observables[0].get_and_load_analysis(IDNAAnalysis)


@pytest.mark.integration
def test_ascii_domain_has_no_analysis(root_analysis):
    _, analysis = _analyze(root_analysis, "example.com")

    assert analysis is False


@pytest.mark.integration
def test_invalid_punycode_is_not_a_crash(root_analysis, caplog):
    # a valid fqdn as far as observable validation goes, but "zz" decodes to nothing
    with caplog.at_level(logging.INFO):
        observable, analysis = _analyze(root_analysis, "xn--zz.com")

    assert analysis is False
    assert "unable to convert xn--zz.com between idna and unicode" in caplog.text


@pytest.mark.unit
def test_summary_without_conversions():
    assert IDNAAnalysis().generate_summary() is None
