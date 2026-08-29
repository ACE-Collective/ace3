"""Tests for the global exclusion branch of
``AnalysisExecutor._process_observable_exclusions``.

``_process_observable_exclusions`` runs once per work item, before any module is
selected, and drops the observable entirely when it matches
``EngineConfiguration.observable_exclusions`` — the ``observable_exclusions:``
section of the layered YAML config (see docs/ENGINE.md §7.5, §19.2).

Two defects are guarded against here. The dict was never populated, so the
branch could not fire at all (covered by the ``EngineConfiguration`` tests in
``test_configuration_manager.py``). And the comparison was
``observable.value in exclusion`` — a *substring* test against the exclusion
string, so an exclusion of ``google.com`` matched an observable of ``oogle.com``
but not ``mail.google.com``. Matching now goes through ``Observable.matches()``,
the same call the module-level exclusions use, which is exact for most types and
CIDR-aware for ``ip``/``ipv4``.

The helper needs nothing but ``self.config.observable_exclusions`` and a
``WorkTarget``, so these are unit tests with no DB and no engine.
"""
from unittest.mock import MagicMock

import pytest

from saq.analysis.root import RootAnalysis
from saq.constants import (
    DIRECTIVE_EXCLUDE_ALL,
    F_FQDN,
    F_IPV4,
    F_URL,
)
from saq.engine.executor import AnalysisExecutor, ObservableExclusionResult
from saq.engine.work_stack import WorkTarget


def _make_executor(observable_exclusions: dict) -> AnalysisExecutor:
    """Minimum-viable AnalysisExecutor for the exclusion helper.

    ``self.config`` is just ``configuration_manager.config``, so the exclusion
    dict is the only attribute that has to be a real value.
    """
    configuration_manager = MagicMock()
    configuration_manager.config.observable_exclusions = observable_exclusions
    return AnalysisExecutor(
        configuration_manager=configuration_manager,
        delayed_analysis_interface=MagicMock(),
        tracking_message_manager=MagicMock(),
        single_threaded_mode=True,
    )


def _make_work_item(tmp_path, o_type: str, o_value: str, dependency=None) -> WorkTarget:
    """A WorkTarget over a real observable of the requested type, so the type's
    own ``matches()`` override (CIDR for ip/ipv4) is what gets exercised."""
    root = RootAnalysis(storage_dir=str(tmp_path))
    observable = root.add_observable_by_spec(o_type, o_value)
    assert observable
    return WorkTarget(observable=observable, dependency=dependency)


@pytest.mark.unit
def test_exclusion_matches_exactly(tmp_path):
    """The whole point: a configured exclusion drops the work item."""
    executor = _make_executor({F_FQDN: ["google.com"]})
    work_item = _make_work_item(tmp_path, F_FQDN, "google.com")

    assert (
        executor._process_observable_exclusions(work_item)
        == ObservableExclusionResult.EXCLUDED
    )


@pytest.mark.unit
def test_exclusion_does_not_match_substring_of_exclusion(tmp_path):
    """``oogle.com`` is a substring of the exclusion ``google.com`` but is a
    different domain -- the old ``value in exclusion`` test excluded it."""
    executor = _make_executor({F_FQDN: ["google.com"]})
    work_item = _make_work_item(tmp_path, F_FQDN, "oogle.com")

    assert (
        executor._process_observable_exclusions(work_item)
        == ObservableExclusionResult.OK
    )


@pytest.mark.unit
def test_exclusion_does_not_match_subdomain(tmp_path):
    """Excluding a domain does not exclude its subdomains."""
    executor = _make_executor({F_FQDN: ["google.com"]})
    work_item = _make_work_item(tmp_path, F_FQDN, "mail.google.com")

    assert (
        executor._process_observable_exclusions(work_item)
        == ObservableExclusionResult.OK
    )


@pytest.mark.unit
def test_exclusion_matches_ipv4_exactly(tmp_path):
    executor = _make_executor({F_IPV4: ["127.0.0.1", "0.0.0.0"]})
    work_item = _make_work_item(tmp_path, F_IPV4, "127.0.0.1")

    assert (
        executor._process_observable_exclusions(work_item)
        == ObservableExclusionResult.EXCLUDED
    )


@pytest.mark.unit
def test_exclusion_matches_ipv4_cidr(tmp_path):
    """CIDR membership comes from ``IPv4Observable.matches``."""
    executor = _make_executor({F_IPV4: ["10.0.0.0/8"]})
    work_item = _make_work_item(tmp_path, F_IPV4, "10.1.2.3")

    assert (
        executor._process_observable_exclusions(work_item)
        == ObservableExclusionResult.EXCLUDED
    )


@pytest.mark.unit
def test_exclusion_ipv4_outside_cidr(tmp_path):
    executor = _make_executor({F_IPV4: ["10.0.0.0/8"]})
    work_item = _make_work_item(tmp_path, F_IPV4, "192.168.1.1")

    assert (
        executor._process_observable_exclusions(work_item)
        == ObservableExclusionResult.OK
    )


@pytest.mark.unit
def test_exclusion_value_containing_a_colon(tmp_path):
    """Exclusion specs split on the first colon only, so a url value keeps its
    scheme separator."""
    executor = _make_executor({F_URL: ["https://google.com/evil"]})
    work_item = _make_work_item(tmp_path, F_URL, "https://google.com/evil")

    assert (
        executor._process_observable_exclusions(work_item)
        == ObservableExclusionResult.EXCLUDED
    )


@pytest.mark.unit
def test_no_exclusion_for_unlisted_type(tmp_path):
    """An observable of a type with no exclusions configured passes through."""
    executor = _make_executor({F_IPV4: ["127.0.0.1"]})
    work_item = _make_work_item(tmp_path, F_FQDN, "google.com")

    assert (
        executor._process_observable_exclusions(work_item)
        == ObservableExclusionResult.OK
    )


@pytest.mark.unit
def test_no_exclusions_configured(tmp_path):
    executor = _make_executor({})
    work_item = _make_work_item(tmp_path, F_FQDN, "google.com")

    assert (
        executor._process_observable_exclusions(work_item)
        == ObservableExclusionResult.OK
    )


@pytest.mark.unit
def test_exclusion_fails_waiting_dependency(tmp_path):
    """A dependency being resolved by an excluded work item has to be failed and
    advanced, otherwise its waiter is stranded."""
    dependency = MagicMock()
    executor = _make_executor({F_FQDN: ["google.com"]})
    work_item = _make_work_item(tmp_path, F_FQDN, "google.com", dependency=dependency)

    assert (
        executor._process_observable_exclusions(work_item)
        == ObservableExclusionResult.EXCLUDED
    )
    dependency.set_status_failed.assert_called_once_with("globally excluded observable")
    dependency.increment_status.assert_called_once()


@pytest.mark.unit
def test_whitelisted_observable_is_excluded(tmp_path):
    """The whitelist check sits above the exclusion check and is unaffected."""
    executor = _make_executor({})
    work_item = _make_work_item(tmp_path, F_FQDN, "google.com")
    work_item.observable.whitelist()

    assert (
        executor._process_observable_exclusions(work_item)
        == ObservableExclusionResult.EXCLUDED
    )


@pytest.mark.unit
def test_exclude_all_directive_is_excluded(tmp_path):
    """The DIRECTIVE_EXCLUDE_ALL check sits below the exclusion check and is
    unaffected."""
    executor = _make_executor({})
    work_item = _make_work_item(tmp_path, F_FQDN, "google.com")
    work_item.observable.add_directive(DIRECTIVE_EXCLUDE_ALL)

    assert (
        executor._process_observable_exclusions(work_item)
        == ObservableExclusionResult.EXCLUDED
    )


@pytest.mark.unit
def test_work_item_without_observable(tmp_path):
    executor = _make_executor({F_FQDN: ["google.com"]})

    assert (
        executor._process_observable_exclusions(WorkTarget())
        == ObservableExclusionResult.OK
    )
