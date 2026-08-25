import os

import pytest

from saq.configuration.config import get_config, get_service_config
from saq.constants import (
    F_EMAIL_ADDRESS,
    F_EMAIL_DKIM_SIGNING_DOMAIN,
    F_EMAIL_FROM,
    F_EMAIL_REPLY_TO,
    F_FQDN,
    SERVICE_YARA_SCANNER,
)
from saq.database.util.observable_detection import create_observable_detection, delete_observable_detection
from saq.observables.export.base import ExportEntry, ObservableExportList
from saq.observables.export.config import ObservableExportConfig
from saq.observables.export.manager import get_observable_exports, run_exports
from saq.observables.export.base import select_detections
from saq.observables.export.state import read_fingerprint, write_fingerprint
from saq.observables.type_hierarchy import get_type_hierarchy
from saq.observables.export.yara import (
    OBSERVABLE_EXPORT_DIR,
    YaraObservableExport,
    format_yara_json_string,
    format_yara_string,
)
from tests.saq.helpers import search_log


def yara_export() -> YaraObservableExport:
    return YaraObservableExport(get_config().get_observable_export_config("yara"))


@pytest.fixture
def export_dir(tmpdir, monkeypatch) -> str:
    """Points the yara export at a temporary signature directory."""
    signature_dir = str(tmpdir / "signatures")
    monkeypatch.setattr(get_service_config(SERVICE_YARA_SCANNER), "signature_dir", signature_dir)
    return os.path.join(signature_dir, OBSERVABLE_EXPORT_DIR)


@pytest.fixture
def state_dir(tmpdir, monkeypatch) -> str:
    """Points the export state at a temporary directory so tests don't share a fingerprint."""
    path = str(tmpdir / "state")
    monkeypatch.setattr("saq.observables.export.state.get_state_dir", lambda: path)
    return path


@pytest.fixture
def detections():
    """Creates detections and removes them afterwards. Yields a function that adds one."""
    created = []

    def _add(observable_type: str, value: str) -> int:
        detection = create_observable_detection(observable_type, value, None)
        created.append(detection.id)
        return detection.id

    yield _add

    for detection_id in created:
        delete_observable_detection(detection_id)


def read_rule(export_dir: str, observable_type: str) -> str:
    with open(os.path.join(export_dir, f"{observable_type}.yar"), "r") as fp:
        return fp.read()


@pytest.fixture
def email_type_hierarchy():
    """Pins the email subtype -> email_address edges the subtype tests rely on.

    etc/observable_types.yaml already declares these in dev and CI, but snapshotting the in-memory
    parent map keeps the tests from depending on which YAML the run happened to load."""
    hierarchy = get_type_hierarchy()
    parent_snapshot = dict(hierarchy._parent)
    hierarchy._parent[F_EMAIL_REPLY_TO] = F_EMAIL_ADDRESS
    hierarchy._parent[F_EMAIL_FROM] = F_EMAIL_ADDRESS
    hierarchy._parent[F_EMAIL_DKIM_SIGNING_DOMAIN] = F_FQDN
    hierarchy._ancestors_cache.clear()
    try:
        yield hierarchy
    finally:
        hierarchy._parent = parent_snapshot
        hierarchy._ancestors_cache.clear()


#
# export list and fingerprinting
#

@pytest.mark.unit
def test_export_list_fingerprint_is_order_independent():
    a = ObservableExportList([ExportEntry(1, "fqdn", "a.com"), ExportEntry(2, "url", "http://b.com")])
    b = ObservableExportList([ExportEntry(2, "url", "http://b.com"), ExportEntry(1, "fqdn", "a.com")])
    assert a.fingerprint() == b.fingerprint()


@pytest.mark.unit
@pytest.mark.parametrize("entries", [
    # added
    [ExportEntry(1, "fqdn", "a.com"), ExportEntry(2, "fqdn", "b.com")],
    # removed
    [],
    # value changed
    [ExportEntry(1, "fqdn", "changed.com")],
    # type changed
    [ExportEntry(1, "url", "a.com")],
])
def test_export_list_fingerprint_changes(entries):
    original = ObservableExportList([ExportEntry(1, "fqdn", "a.com")])
    assert original.fingerprint() != ObservableExportList(entries).fingerprint()


@pytest.mark.unit
def test_export_list_entries_by_type():
    export_list = ObservableExportList([
        ExportEntry(2, "fqdn", "b.com"),
        ExportEntry(1, "fqdn", "a.com"),
        ExportEntry(3, "url", "http://c.com"),
    ])

    assert export_list.types == ["fqdn", "url"]
    grouped = export_list.entries_by_type()
    assert [entry.id for entry in grouped["fqdn"]] == [1, 2]
    assert [entry.id for entry in grouped["url"]] == [3]


#
# state
#

@pytest.mark.unit
def test_state_round_trip(state_dir):
    assert read_fingerprint("test_target") is None
    write_fingerprint("test_target", "abc123")
    assert read_fingerprint("test_target") == "abc123"


@pytest.mark.unit
def test_state_ignores_malformed_file(state_dir):
    os.makedirs(state_dir)
    with open(os.path.join(state_dir, "test_target.json"), "w") as fp:
        fp.write("this is not json")

    # a corrupt state file must not stop the export -- it reads as "never published"
    assert read_fingerprint("test_target") is None


#
# target selection
#

@pytest.mark.unit
def test_get_observable_exports_defaults_to_enabled():
    assert "yara" in [export.name for export in get_observable_exports()]


@pytest.mark.unit
def test_get_observable_exports_by_name():
    exports = get_observable_exports(["yara"])
    assert len(exports) == 1
    assert isinstance(exports[0], YaraObservableExport)


@pytest.mark.unit
def test_get_observable_exports_skips_disabled(monkeypatch):
    monkeypatch.setattr(get_config().get_observable_export_config("yara"), "enabled", False)
    assert "yara" not in [export.name for export in get_observable_exports()]


@pytest.mark.unit
def test_get_observable_exports_unknown_name():
    with pytest.raises(ValueError):
        get_observable_exports(["does_not_exist"])


@pytest.mark.unit
def test_run_exports_unknown_name_is_a_usage_error(state_dir):
    assert run_exports(["does_not_exist"]) == os.EX_USAGE


@pytest.mark.unit
def test_get_config_class_is_the_base_by_default():
    assert YaraObservableExport.get_config_class() is ObservableExportConfig


#
# yara: building the export list
#

@pytest.mark.unit
def test_build_export_list_filters_by_type_and_length(monkeypatch):
    monkeypatch.setattr(get_config().yara_export, "export_list", ["fqdn", "ip"])
    monkeypatch.setattr(get_config().yara_export, "export_minimum_length", 5)

    export_list = yara_export().build_export_list({
        "fqdn": [{"id": 1, "value": "evil.example.com"}],
        "ip": [{"id": 2, "value": "192.168.1.1"}, {"id": 3, "value": "::1"}],
        "url": [{"id": 4, "value": "http://not-configured.example.com"}],
    })

    # ::1 is under the minimum length, url is not a configured type
    assert {(entry.type, entry.id) for entry in export_list} == {("fqdn", 1), ("ip", 2)}


#
# subtype selection: an export_list entry covers the types that extend it
#

@pytest.mark.unit
def test_select_detections_includes_subtypes(email_type_hierarchy):
    selected = list(select_detections(
        {
            F_EMAIL_REPLY_TO: [{"id": 1, "value": "a@example.com"}],
            F_EMAIL_FROM: [{"id": 2, "value": "b@example.com"}],
            F_EMAIL_ADDRESS: [{"id": 3, "value": "c@example.com"}],
        },
        [F_EMAIL_ADDRESS]))

    # every one is covered, and every one is reported under the configured type
    assert sorted((export_type, detection["id"]) for export_type, detection in selected) == [
        (F_EMAIL_ADDRESS, 1), (F_EMAIL_ADDRESS, 2), (F_EMAIL_ADDRESS, 3)]


@pytest.mark.unit
def test_select_detections_most_specific_configured_type_wins(email_type_hierarchy):
    selected = list(select_detections(
        {F_EMAIL_REPLY_TO: [{"id": 1, "value": "a@example.com"}]},
        [F_EMAIL_ADDRESS, F_EMAIL_REPLY_TO]))

    # exported once, under the more specific of the two configured types
    assert selected == [(F_EMAIL_REPLY_TO, {"id": 1, "value": "a@example.com"})]


@pytest.mark.unit
def test_select_detections_ignores_unrelated_types(email_type_hierarchy):
    assert list(select_detections(
        {"url": [{"id": 1, "value": "http://example.com"}]}, [F_EMAIL_ADDRESS, F_FQDN])) == []


@pytest.mark.unit
def test_select_detections_ignores_blank_configured_entries(email_type_hierarchy):
    assert list(select_detections({"": [{"id": 1, "value": "x"}]}, ["", "   "])) == []


@pytest.mark.unit
def test_build_export_list_includes_subtypes(monkeypatch, email_type_hierarchy):
    monkeypatch.setattr(get_config().yara_export, "export_list", [F_EMAIL_ADDRESS])
    monkeypatch.setattr(get_config().yara_export, "export_minimum_length", 5)

    export_list = yara_export().build_export_list({
        F_EMAIL_REPLY_TO: [{"id": 1, "value": "reply@example.com"}],
        F_EMAIL_FROM: [{"id": 2, "value": "from@example.com"}],
        F_EMAIL_ADDRESS: [{"id": 3, "value": "plain@example.com"}],
    })

    assert {(entry.type, entry.id) for entry in export_list} == {
        (F_EMAIL_ADDRESS, 1), (F_EMAIL_ADDRESS, 2), (F_EMAIL_ADDRESS, 3)}


@pytest.mark.unit
def test_build_export_list_most_specific_configured_type_wins(monkeypatch, email_type_hierarchy):
    monkeypatch.setattr(
        get_config().yara_export, "export_list", [F_EMAIL_ADDRESS, F_EMAIL_REPLY_TO])
    monkeypatch.setattr(get_config().yara_export, "export_minimum_length", 5)

    export_list = yara_export().build_export_list({
        F_EMAIL_REPLY_TO: [{"id": 1, "value": "reply@example.com"}],
    })

    assert [(entry.type, entry.id) for entry in export_list] == [(F_EMAIL_REPLY_TO, 1)]


@pytest.mark.unit
def test_build_export_list_applies_minimum_length_to_subtypes(monkeypatch, email_type_hierarchy):
    monkeypatch.setattr(get_config().yara_export, "export_list", [F_EMAIL_ADDRESS])
    monkeypatch.setattr(get_config().yara_export, "export_minimum_length", 5)

    export_list = yara_export().build_export_list({
        F_EMAIL_REPLY_TO: [{"id": 1, "value": "a@b"}, {"id": 2, "value": "reply@example.com"}],
    })

    assert [(entry.type, entry.id) for entry in export_list] == [(F_EMAIL_ADDRESS, 2)]


@pytest.mark.unit
def test_string_modifiers():
    export = yara_export()
    # fqdn has an explicit mapping, ip does not and falls back to the default. This is the
    # regression test for the modifier lookup that used to raise AttributeError on every type
    # without an explicit mapping.
    assert export.get_string_modifiers("fqdn") == "ascii wide nocase fullword"
    assert export.get_string_modifiers("ip") == "ascii wide nocase"


@pytest.mark.unit
def test_format_yara_string():
    assert format_yara_string('a"b\\c\r\nd') == 'a\\"b\\\\cd'
    # a value embedded in JSON carries twice the backslashes
    assert format_yara_json_string('a\\c') == 'a\\\\\\\\c'


#
# yara: publishing
#

@pytest.mark.integration
def test_export_writes_compilable_rules(export_dir, state_dir, detections):
    import yara

    fqdn_id = detections("fqdn", "evil.example.com")
    email_id = detections("email_address", "attacker@example.com")

    assert run_exports() == os.EX_OK

    fqdn_rule = read_rule(export_dir, "fqdn")
    assert f"$obsd_{fqdn_id}" in fqdn_rule
    assert "evil.example.com" in fqdn_rule
    assert "rule detect_fqdn : detect_fqdn" in fqdn_rule
    yara.compile(source=fqdn_rule)

    # email_address has its own template, which scopes the rule to the email parts
    email_rule = read_rule(export_dir, "email_address")
    assert f"$obsd_{email_id}" in email_rule
    assert "email.rfc822.headers" in email_rule
    yara.compile(source=email_rule)


@pytest.mark.integration
def test_export_skips_when_nothing_changed(export_dir, state_dir, detections):
    detections("fqdn", "evil.example.com")

    assert run_exports() == os.EX_OK
    mtime = os.path.getmtime(os.path.join(export_dir, "fqdn.yar"))

    assert run_exports() == os.EX_OK
    assert search_log("no updates needed for observable export yara")
    assert os.path.getmtime(os.path.join(export_dir, "fqdn.yar")) == mtime


@pytest.mark.integration
def test_export_force_ignores_the_change_check(export_dir, state_dir, detections):
    detections("fqdn", "evil.example.com")

    assert run_exports() == os.EX_OK
    os.remove(os.path.join(export_dir, "fqdn.yar"))

    # without --force this would be a no-op and the deleted file would stay gone
    assert run_exports(force=True) == os.EX_OK
    assert os.path.exists(os.path.join(export_dir, "fqdn.yar"))


@pytest.mark.integration
def test_export_prunes_stale_rule_files(export_dir, state_dir, detections):
    fqdn_id = detections("fqdn", "evil.example.com")
    detections("email_address", "attacker@example.com")

    assert run_exports() == os.EX_OK
    assert os.path.exists(os.path.join(export_dir, "fqdn.yar"))

    delete_observable_detection(fqdn_id)
    assert run_exports() == os.EX_OK

    # the type has nothing left to export, so its rule file must go -- otherwise a disabled
    # detection keeps firing
    assert not os.path.exists(os.path.join(export_dir, "fqdn.yar"))
    assert os.path.exists(os.path.join(export_dir, "email_address.yar"))


@pytest.mark.integration
def test_export_escapes_quotes_and_backslashes(export_dir, state_dir, detections):
    import yara

    detection_id = detections("url", 'http://bad.example.com/a"b\\c')

    assert run_exports() == os.EX_OK

    rule = read_rule(export_dir, "url")
    yara.compile(source=rule)
    assert f'$obsd_{detection_id} = "http://bad.example.com/a\\"b\\\\c"' in rule
    # the json form differs, so it gets its own string
    assert f"$obsd_json_{detection_id}" in rule


@pytest.mark.integration
def test_export_applies_string_modifiers(export_dir, state_dir, detections):
    detections("fqdn", "evil.example.com")
    detections("ip", "192.168.44.100")

    assert run_exports() == os.EX_OK

    assert "fullword" in read_rule(export_dir, "fqdn")
    # ip has no explicit mapping, so it gets the default set
    ip_rule = read_rule(export_dir, "ip")
    assert "ascii wide nocase" in ip_rule
    assert "fullword" not in ip_rule


@pytest.mark.integration
def test_export_handles_ipv4_ipv6_and_the_legacy_type(export_dir, state_dir, detections):
    import yara

    v4_id = detections("ip", "192.168.44.100")
    v6_id = detections("ip", "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    legacy_id = detections("ipv4", "10.20.30.40")

    assert run_exports() == os.EX_OK

    # both address families live under the generic ip type
    ip_rule = read_rule(export_dir, "ip")
    yara.compile(source=ip_rule)
    assert f"$obsd_{v4_id}" in ip_rule
    assert f"$obsd_{v6_id}" in ip_rule
    assert 'file_ext = "!bmp"' in ip_rule

    # detections created before the migration to the generic type still export
    legacy_rule = read_rule(export_dir, "ipv4")
    yara.compile(source=legacy_rule)
    assert f"$obsd_{legacy_id}" in legacy_rule


@pytest.mark.integration
def test_export_writes_subtype_detections_into_the_parent_rule_file(
        export_dir, state_dir, detections, email_type_hierarchy):
    import yara

    reply_to_id = detections(F_EMAIL_REPLY_TO, "reply@example.com")
    plain_id = detections(F_EMAIL_ADDRESS, "plain@example.com")

    assert run_exports() == os.EX_OK

    # email_reply_to is not in the export_list -- email_address is, and it covers it
    rule = read_rule(export_dir, F_EMAIL_ADDRESS)
    assert f"$obsd_{reply_to_id}" in rule
    assert "reply@example.com" in rule
    assert f"$obsd_{plain_id}" in rule
    yara.compile(source=rule)

    # the subtype must not get a rule file of its own: it has no template and no configured search
    assert not os.path.exists(os.path.join(export_dir, f"{F_EMAIL_REPLY_TO}.yar"))


@pytest.mark.integration
def test_export_applies_parent_string_modifiers_to_subtypes(
        export_dir, state_dir, detections, email_type_hierarchy):
    detections(F_EMAIL_DKIM_SIGNING_DOMAIN, "evil.example.com")

    assert run_exports() == os.EX_OK

    # exported under fqdn, so it picks up the fullword modifier configured for that type
    rule = read_rule(export_dir, F_FQDN)
    assert "evil.example.com" in rule
    assert "fullword" in rule
    assert not os.path.exists(os.path.join(export_dir, f"{F_EMAIL_DKIM_SIGNING_DOMAIN}.yar"))


@pytest.mark.integration
def test_export_falls_back_to_the_default_template(export_dir, state_dir, detections):
    # user_agent has no template of its own
    detections("user_agent", "Mozilla/4.0 (compatible; Evil)")

    assert run_exports() == os.EX_OK

    rule = read_rule(export_dir, "user_agent")
    assert "rule detect_user_agent : detect_user_agent" in rule
    # the default template carries no per-type meta scoping
    assert "file_name" not in rule


@pytest.mark.integration
def test_export_survives_a_missing_template_dir(export_dir, state_dir, detections, monkeypatch, tmpdir):
    monkeypatch.setattr(get_config().yara_export, "export_template_dir", str(tmpdir / "does_not_exist"))
    detections("fqdn", "evil.example.com")

    # a missing template skips the type rather than aborting the whole run
    assert run_exports() == os.EX_OK
    assert search_log("unable to read yara export template")
    assert not os.path.exists(os.path.join(export_dir, "fqdn.yar"))
