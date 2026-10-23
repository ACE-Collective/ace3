import copy
import logging

import pytest

from saq.analysis.root import load_root
from saq.constants import F_EMAIL_ADDRESS, F_USER
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules import user as user_module
from saq.modules.user import UserAnalysis
from saq.util.uuid import get_storage_dir

# a reporting chain under the configured top_user (ldap.top_user: theboss), whose own entry has
# no manager, as the top of a directory usually doesn't
DIRECTORY = {
    "theboss": {"cn": "theboss", "mail": "The.Boss@company.com", "displayName": "Boss, The"},
    "vp": {"cn": "vp", "mail": "vp@company.com", "manager_cn": "theboss"},
    "director": {"cn": "director", "mail": "director@company.com", "manager_cn": "vp"},
    "engineer": {"cn": "Engineer", "mail": "engineer@company.com", "manager_cn": "director",
                 "displayName": "Engineer, Some", "l": "Cincinnati", "division": "IT", "title": "Engineer",
                 "memberOf": ["CN=Domain Admins,DC=company,DC=com", "CN=Staff,DC=company,DC=com"]},
    "orphan": {"cn": "orphan", "mail": "orphan@company.com", "manager_cn": "departed"},
}


@pytest.fixture
def directory(monkeypatch):
    lookups = []

    def lookup_user(cn):
        lookups.append(cn)
        entry = DIRECTORY.get(cn.lower())
        return copy.deepcopy(entry) if entry else None

    def lookup_email_address(address):
        lookups.append(address)
        for entry in DIRECTORY.values():
            if entry["mail"].lower() == address.lower():
                return copy.deepcopy(entry)
        return None

    monkeypatch.setattr(user_module, "lookup_user", lookup_user)
    monkeypatch.setattr(user_module, "lookup_email_address", lookup_email_address)
    return lookups


def _analyze(root_analysis, observable_type, value, directives=()):
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(observable_type, value)
    for directive in directives:
        observable.add_directive(directive)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("user_analyzer", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    observable = root_analysis.get_observable(observable.uuid)
    return observable, observable.get_and_load_analysis(UserAnalysis)


@pytest.mark.parametrize("cn, executive", [
    ("theboss", True),
    ("vp", True),
    ("director", True),
    ("engineer", False),
])
@pytest.mark.integration
def test_executive_within_two_managers_of_the_top_user(root_analysis, directory, cn, executive):
    observable, analysis = _analyze(root_analysis, F_USER, cn)

    assert isinstance(analysis, UserAnalysis)
    assert observable.has_tag("executive") is executive


@pytest.mark.integration
def test_email_address_of_the_top_user_is_executive(root_analysis, directory):
    observable, analysis = _analyze(root_analysis, F_EMAIL_ADDRESS, "the.boss@company.com", directives=["sandbox"])

    assert isinstance(analysis, UserAnalysis)
    assert observable.has_tag("executive")

    # the user observable it adds is not analyzed again, and carries the email address's directives
    users = analysis.get_observables_by_type(F_USER)
    assert [u.value for u in users] == ["theboss"]
    assert users[0].has_directive("skip_user_analysis")
    assert users[0].has_directive("sandbox")


@pytest.mark.integration
def test_user_adds_normalized_email_address(root_analysis, directory):
    _, analysis = _analyze(root_analysis, F_USER, "theboss")

    addresses = analysis.get_observables_by_type(F_EMAIL_ADDRESS)
    assert [a.value for a in addresses] == ["the.boss@company.com"]
    assert addresses[0].has_directive("skip_user_analysis")
    # theboss has no manager to look up
    assert "manager_ldap" not in analysis.details


@pytest.mark.integration
def test_details_and_summary(root_analysis, directory):
    _, analysis = _analyze(root_analysis, F_USER, "engineer")

    assert analysis.details["manager_ldap"]["cn"] == "director"
    assert analysis.details["ldap"]["entitlements"] == [
        {"group": "CN=Domain Admins,DC=company,DC=com", "privileged": False},
        {"group": "CN=Staff,DC=company,DC=com", "privileged": False},
    ]
    assert analysis.generate_summary() == "Engineer, Some - Cincinnati - IT - Engineer"


@pytest.mark.integration
def test_missing_manager_is_logged(root_analysis, directory, caplog):
    with caplog.at_level(logging.ERROR):
        observable, analysis = _analyze(root_analysis, F_USER, "orphan")

    assert isinstance(analysis, UserAnalysis)
    assert analysis.details["manager_ldap"] is None
    assert not observable.has_tag("executive")
    assert "Failed to fetch manger ldap info for orphan" in caplog.text
    assert analysis.generate_summary() == "None, None - None - None - None"


@pytest.mark.parametrize("observable_type, value, looked_up", [
    # external addresses are never looked up
    (F_EMAIL_ADDRESS, "someone@external.example", False),
    (F_EMAIL_ADDRESS, "nobody@company.com", True),
    (F_USER, "nobody", True),
])
@pytest.mark.integration
def test_no_analysis_without_a_directory_entry(root_analysis, directory, observable_type, value, looked_up):
    _, analysis = _analyze(root_analysis, observable_type, value)

    assert analysis is False
    assert (value in directory) is looked_up


@pytest.mark.integration
def test_skip_user_analysis_directive(root_analysis, directory):
    _, analysis = _analyze(root_analysis, F_USER, "theboss", directives=["skip_user_analysis"])

    assert analysis is False
    assert directory == []
