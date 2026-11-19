"""The alert-management filter query builder, run outside Flask.

The search API and the GUI run the same filter lists, so the query builder has to work with
no current_user and no request context -- that is most of what this file asserts.
"""

import hashlib
from datetime import datetime
from types import SimpleNamespace

import pymysql
import pytest
import pytz
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import aliased

from saq.database.model import (
    Alert,
    AnalysisMapping,
    AnalysisType,
    DetectionPoint,
    Observable,
    Tag,
    TagMapping,
)
from saq.database.pool import get_db
from saq.gui import filter_query
from saq.gui.filter_query import (
    ANY_OBSERVABLE_TYPE,
    AnalysisFilter,
    build_alert_query,
    count_alerts,
    filter_alert_uuids,
    get_analysis_type_labels,
)
from saq.gui.observable_pattern import ObservablePatternError
from tests.saq.helpers import attach_observable, insert_alert, insert_alert_with_detections

pytestmark = pytest.mark.integration

SIGNATURE_UUID = "6f3a1b2c-1111-2222-3333-444455556666"
QR_CODE_ANALYSIS = "saq.modules.file_analysis.qrcode:QRCodeAnalysis"
URL_EXTRACTION_ANALYSIS = "saq.modules.file_analysis.url_extraction:URLExtractionAnalysis"
SPLUNK_SESSION_ACTIVITY = "saq.modules.splunk:SplunkAPIAnalysis:session_activity"
OTHER_SIGNATURE_UUID = "9b21c3d4-aaaa-bbbb-cccc-ddddeeeeffff"


def _tag(alert: Alert, name: str) -> None:
    db = get_db()
    tag = db.query(Tag).filter(Tag.name == name).one_or_none()
    if tag is None:
        tag = Tag(name=name)
        db.add(tag)
        db.flush()
    db.add(TagMapping(tag_id=tag.id, alert_id=alert.id))
    db.commit()


def _detection_point(alert: Alert, signature_uuid: str, signature_version: str) -> None:
    db = get_db()
    content_hash = hashlib.sha256(f"{alert.id}:{signature_uuid}:{signature_version}".encode()).hexdigest()
    db.add(DetectionPoint(alert_id=alert.id, description=f"detected by {signature_uuid}",
                          signature_uuid=signature_uuid, signature_version=signature_version,
                          content_hash=content_hash))
    db.commit()


def _analysis(alert: Alert, module_path: str, display_name: str) -> None:
    """Maps an analysis type to an alert, reusing the catalog row if it already exists."""
    db = get_db()
    analysis_type = db.query(AnalysisType).filter(AnalysisType.module_path == module_path).one_or_none()
    if analysis_type is None:
        analysis_type = AnalysisType(module_path=module_path, display_name=display_name)
        db.add(analysis_type)
        db.flush()
    db.add(AnalysisMapping(alert_id=alert.id, analysis_type_id=analysis_type.id))
    db.commit()


def _uuids(filters):
    query = build_alert_query(filters, entity=Alert, tz=pytz.utc, locations=None)
    return {row[0] for row in query.with_entities(Alert.uuid).distinct()}


@pytest.fixture
def corpus():
    db = get_db()
    signed = insert_alert()
    tagged = insert_alert()
    plain = insert_alert()
    db.execute(Alert.__table__.update().where(Alert.id == signed.id).values(insert_date=datetime(2026, 1, 1), queue="external"))
    db.execute(Alert.__table__.update().where(Alert.id == tagged.id).values(insert_date=datetime(2026, 2, 1)))
    db.commit()

    attach_observable(signed, "signature_id", SIGNATURE_UUID)
    attach_observable(signed, "ipv4", "10.20.30.40")
    attach_observable(tagged, "ipv4", "203.0.113.7")
    _tag(tagged, "credential-harvest")
    # a tag of another name, which the Tag filter must tell apart
    _tag(signed, "phishing")
    return signed, tagged, plain


class TestObservableFilter:
    def test_finds_alerts_carrying_a_signature_uuid_observable(self, corpus):
        """The use case this whole filter path exists to serve."""
        signed, _, _ = corpus
        assert _uuids([{"name": "Observable", "inverted": False,
                        "values": [["signature_id", SIGNATURE_UUID]]}]) == {signed.uuid}

    def test_type_and_value_must_both_match(self, corpus):
        """`hostname` accepts the value, so this reaches the lookup: the (type, sha256) pair
        has to match, not the value's digest alone."""
        assert _uuids([{"name": "Observable", "inverted": False,
                        "values": [["hostname", SIGNATURE_UUID]]}]) == set()

    def test_value_is_normalized_the_way_the_engine_normalizes_it(self, corpus):
        """Matching on (type, sha256) after resolve_observable_identity(), not on the raw
        value BLOB: an email address is stored lowercased, so both spellings have to find it."""
        signed, _, _ = corpus
        attach_observable(signed, "email_address", "bob@example.com")
        for spelling in ("bob@example.com", "Bob@Example.com"):
            assert _uuids([{"name": "Observable", "inverted": False,
                            "values": [["email_address", spelling]]}]) == {signed.uuid}

    def test_any_type_matches_on_value_alone(self, corpus):
        signed, _, _ = corpus
        assert _uuids([{"name": "Observable", "inverted": False,
                        "values": [[ANY_OBSERVABLE_TYPE, SIGNATURE_UUID]]}]) == {signed.uuid}

    def test_values_within_one_entry_are_ored(self, corpus):
        signed, tagged, _ = corpus
        assert _uuids([{"name": "Observable", "inverted": False,
                        "values": [["ipv4", "10.20.30.40"], ["ipv4", "203.0.113.7"]]}]) == {signed.uuid, tagged.uuid}

    def test_separate_entries_are_anded(self, corpus):
        signed, _, _ = corpus
        both = [
            {"name": "Observable", "inverted": False, "values": [["signature_id", SIGNATURE_UUID]]},
            {"name": "Observable", "inverted": False, "values": [["ipv4", "10.20.30.40"]]},
        ]
        assert _uuids(both) == {signed.uuid}

        neither = both + [{"name": "Observable", "inverted": False, "values": [["ipv4", "203.0.113.7"]]}]
        assert _uuids(neither) == set()

    def test_inverted_keeps_alerts_with_no_observables_at_all(self, corpus):
        """The EXISTS form matters: a plain NOT over the outer join drops alerts that have no
        observable rows, which is the opposite of what "not this observable" means."""
        _, tagged, plain = corpus
        found = _uuids([{"name": "Observable", "inverted": True,
                         "values": [["signature_id", SIGNATURE_UUID]]}])
        assert {tagged.uuid, plain.uuid}.issubset(found)

    def test_an_impossible_value_matches_nothing_rather_than_raising(self, corpus):
        """A saved filter or a pasted link can carry anything; a 500 would lock the analyst
        out of a page they cannot leave without clearing cookies."""
        assert _uuids([{"name": "Observable", "inverted": False,
                        "values": [["ipv4", "not-an-ip"]]}]) == set()


@pytest.fixture
def detections():
    """v1 and v2 of one signature on two alerts, a second signature on a third, and an alert
    with no detection points at all."""
    v1, v2, other, none = insert_alert(), insert_alert(), insert_alert(), insert_alert()
    _detection_point(v1, SIGNATURE_UUID, "v1")
    _detection_point(v2, SIGNATURE_UUID, "v2")
    _detection_point(other, OTHER_SIGNATURE_UUID, "abc123:def")
    return v1, v2, other, none


def _detection_filter(*values, inverted=False):
    return [{"name": "Detection Point", "inverted": inverted, "values": list(values)}]


class TestDetectionPointFilter:
    def test_uuid_alone_matches_every_version(self, detections):
        v1, v2, _, _ = detections
        assert _uuids(_detection_filter(SIGNATURE_UUID)) == {v1.uuid, v2.uuid}

    def test_uuid_and_version_matches_that_version_only(self, detections):
        v1, v2, _, _ = detections
        assert _uuids(_detection_filter(f"{SIGNATURE_UUID}:v1")) == {v1.uuid}
        assert _uuids(_detection_filter(f"{SIGNATURE_UUID}:v2")) == {v2.uuid}
        assert _uuids(_detection_filter(f"{SIGNATURE_UUID}:v3")) == set()

    def test_version_splits_at_the_first_colon(self, detections):
        _, _, other, _ = detections
        assert _uuids(_detection_filter(f"{OTHER_SIGNATURE_UUID}:abc123:def")) == {other.uuid}

    def test_uuid_is_case_insensitive(self, detections):
        v1, v2, _, _ = detections
        assert _uuids(_detection_filter(SIGNATURE_UUID.upper())) == {v1.uuid, v2.uuid}

    def test_values_within_one_entry_are_ored(self, detections):
        v1, _, other, _ = detections
        assert _uuids(_detection_filter(f"{SIGNATURE_UUID}:v1", OTHER_SIGNATURE_UUID)) == {v1.uuid, other.uuid}

    def test_inverted_keeps_alerts_with_no_detection_points(self, detections):
        v1, v2, other, none = detections
        found = _uuids(_detection_filter(SIGNATURE_UUID, inverted=True))
        assert {other.uuid, none.uuid}.issubset(found)
        assert not {v1.uuid, v2.uuid} & found

    def test_an_impossible_value_matches_nothing_rather_than_raising(self, detections):
        assert _uuids(_detection_filter("not-a-uuid")) == set()
        assert _uuids(_detection_filter(f"{SIGNATURE_UUID}:")) == set()


@pytest.fixture
def analyzed():
    """One alert with a QR code, one with a QR code and extracted URLs, one with only the output
    of one instance of an instanced module, and one with no indexed analysis at all."""
    qr, qr_and_urls, instanced, none = insert_alert(), insert_alert(), insert_alert(), insert_alert()
    _analysis(qr, QR_CODE_ANALYSIS, "QR Code Analysis")
    _analysis(qr_and_urls, QR_CODE_ANALYSIS, "QR Code Analysis")
    _analysis(qr_and_urls, URL_EXTRACTION_ANALYSIS, "URL Extraction Analysis")
    _analysis(instanced, SPLUNK_SESSION_ACTIVITY, "SplunkAPIAnalysis (session_activity)")
    return qr, qr_and_urls, instanced, none


def _analysis_filter(*values, inverted=False):
    return [{"name": "Analysis", "inverted": inverted, "values": list(values)}]


class TestAnalysisFilter:
    def test_finds_alerts_containing_the_analysis_type(self, analyzed):
        qr, qr_and_urls, _, _ = analyzed
        assert _uuids(_analysis_filter(QR_CODE_ANALYSIS)) == {qr.uuid, qr_and_urls.uuid}

    def test_instances_are_separate_types(self, analyzed):
        _, _, instanced, _ = analyzed
        assert _uuids(_analysis_filter(SPLUNK_SESSION_ACTIVITY)) == {instanced.uuid}
        assert _uuids(_analysis_filter("saq.modules.splunk:SplunkAPIAnalysis")) == set()

    def test_values_within_one_entry_are_ored(self, analyzed):
        qr, qr_and_urls, instanced, _ = analyzed
        assert _uuids(_analysis_filter(QR_CODE_ANALYSIS, SPLUNK_SESSION_ACTIVITY)) == {
            qr.uuid, qr_and_urls.uuid, instanced.uuid}

    def test_separate_entries_are_anded(self, analyzed):
        _, qr_and_urls, _, _ = analyzed
        assert _uuids(_analysis_filter(QR_CODE_ANALYSIS) + _analysis_filter(URL_EXTRACTION_ANALYSIS)) == {
            qr_and_urls.uuid}

    def test_inverted_keeps_alerts_with_no_indexed_analysis(self, analyzed):
        qr, qr_and_urls, instanced, none = analyzed
        found = _uuids(_analysis_filter(QR_CODE_ANALYSIS, inverted=True))
        assert {instanced.uuid, none.uuid}.issubset(found)
        assert not {qr.uuid, qr_and_urls.uuid} & found

    def test_an_unknown_or_impossible_value_matches_nothing_rather_than_raising(self, analyzed):
        assert _uuids(_analysis_filter("saq.modules.gone:RemovedAnalysis")) == set()
        assert _uuids(_analysis_filter(["not", "a string"])) == set()

    def test_count_alerts(self, analyzed):
        assert count_alerts(_analysis_filter(QR_CODE_ANALYSIS), entity=Alert, tz=pytz.utc, locations=None) == 2

    def test_options_are_the_types_alerts_contain_by_label(self, analyzed):
        db = get_db()
        db.add(AnalysisType(module_path="saq.modules.gone:RemovedAnalysis", display_name="Removed Analysis"))
        db.commit()

        # a catalogued type no alert contains is not offered
        assert AnalysisFilter(AnalysisType.module_path).options == [
            (QR_CODE_ANALYSIS, "QR Code Analysis"),
            (SPLUNK_SESSION_ACTIVITY, "SplunkAPIAnalysis (session_activity)"),
            (URL_EXTRACTION_ANALYSIS, "URL Extraction Analysis"),
        ]

    def test_deleting_the_last_alert_with_a_type_drops_it_from_the_options(self, analyzed):
        _, _, instanced, _ = analyzed
        db = get_db()
        db.execute(Alert.__table__.delete().where(Alert.id == instanced.id))
        db.commit()

        assert SPLUNK_SESSION_ACTIVITY not in dict(AnalysisFilter(AnalysisType.module_path).options)

    def test_labels_for_the_filter_bar(self, analyzed):
        assert get_analysis_type_labels([QR_CODE_ANALYSIS, "saq.modules.gone:RemovedAnalysis", ["x"]]) == {
            QR_CODE_ANALYSIS: "QR Code Analysis"}
        assert get_analysis_type_labels([]) == {}


# a suffix longer than observables.value_rev keeps of a value's end (OBSERVABLE_VALUE_REV_LENGTH)
LONG_SUFFIX = " --payload " + "A" * 300


def _pattern(*pairs, inverted=False):
    return [{"name": "Observable Pattern", "inverted": inverted, "values": [list(pair) for pair in pairs]}]


@pytest.fixture
def patterned():
    """Alerts whose observables tell each kind of pattern apart."""
    subdomain, lookalike, shouty, literal, plain = (insert_alert() for _ in range(5))
    attach_observable(subdomain, "fqdn", "mail.evil.com")
    attach_observable(subdomain, "url", "https://evil.com/login?next=1")
    attach_observable(subdomain, "file_path", "C:\\Users\\bob\\AppData\\evil.exe")
    attach_observable(lookalike, "fqdn", "evil.com.attacker.net")
    attach_observable(lookalike, "email_address", "bob@evil.com")
    attach_observable(lookalike, "command_line", "powershell -nop" + LONG_SUFFIX)
    # the fqdn class keeps the case it is given, so this is its own observable
    attach_observable(shouty, "fqdn", "Mail.EVIL.com")
    # LIKE's own wildcards and the escape character, as literal text
    attach_observable(literal, "file_name", "50%_off!.exe")
    attach_observable(literal, "file_name", "50ab_off!.exe")
    # the same last 255 bytes as lookalike's command line, but not the same suffix
    attach_observable(literal, "command_line", "cmd /c" + "B" + LONG_SUFFIX[1:])
    return SimpleNamespace(subdomain=subdomain, lookalike=lookalike, shouty=shouty, literal=literal, plain=plain)


class TestObservablePatternFilter:
    def test_value_rev_is_the_value_reversed(self, patterned):
        """The migration's generated column: what the suffix index is built from."""
        value_rev = get_db().query(Observable.value_rev).filter(Observable.value == b"mail.evil.com").scalar()
        assert value_rev == b"moc.live.liam"

    def test_value_rev_keeps_the_end_of_a_long_value(self, patterned):
        value = ("powershell -nop" + LONG_SUFFIX).encode()
        value_rev = get_db().query(Observable.value_rev).filter(Observable.value == value).scalar()
        assert value_rev == value[::-1][:255]

    def test_suffix(self, patterned):
        assert _uuids(_pattern(["fqdn", "*.evil.com"])) == {patterned.subdomain.uuid}

    def test_prefix(self, patterned):
        assert _uuids(_pattern(["url", "https://evil.com/*"])) == {patterned.subdomain.uuid}

    def test_text_at_both_ends_with_a_wildcard_between(self, patterned):
        assert _uuids(_pattern(["fqdn", "evil.com*.net"])) == {patterned.lookalike.uuid}

    def test_windows_backslashes_are_literal(self, patterned):
        assert _uuids(_pattern(["file_path", "C:\\Users\\*\\evil.exe"])) == {patterned.subdomain.uuid}

    def test_the_type_must_match(self, patterned):
        assert _uuids(_pattern(["hostname", "*.evil.com"])) == set()

    def test_any_type(self, patterned):
        assert _uuids(_pattern([ANY_OBSERVABLE_TYPE, "*evil.com"])) == {patterned.subdomain.uuid, patterned.lookalike.uuid}

    def test_the_match_keeps_case_for_a_type_whose_class_keeps_it(self, patterned):
        """As the exact Observable filter does: fqdn stores what it was given."""
        assert _uuids(_pattern(["fqdn", "*.EVIL.com"])) == {patterned.shouty.uuid}
        assert _uuids(_pattern(["fqdn", "*.Evil.com"])) == set()

    def test_the_pattern_is_lowercased_for_a_type_whose_class_lowercases(self, patterned):
        """email_address stores addresses lowercased, so its pattern is lowercased too."""
        assert _uuids(_pattern(["email_address", "*@Evil.COM"])) == {patterned.lookalike.uuid}

    def test_a_class_that_rewrites_more_than_case_is_not_used(self):
        """The user class drops a `DOMAIN\\`, which would turn the anchored `CORP\\*evil*` into
        `*evil*` after its shape was checked: a pattern no index serves."""
        assert filter_query.normalize_observable_pattern("user", "CORP\\*evil*") == "CORP\\*evil*"
        attach_observable(insert_alert(), "user", "xevilx")
        assert _uuids(_pattern(["user", "CORP\\*evil*"])) == set()

    def test_like_wildcards_and_the_escape_character_are_literal(self, patterned):
        """Unescaped, `50%_off!*` would also match 50ab_off!.exe."""
        observables = get_db().query(Observable.value).filter(
            Observable.id.in_(filter_query.resolve_observable_pattern("file_name", "50%_off!*")))
        assert [row[0] for row in observables] == [b"50%_off!.exe"]

    def test_a_suffix_longer_than_value_rev_is_checked_against_the_whole_value(self, patterned):
        """The index matches only its last 255 bytes; both command lines share those."""
        assert _uuids(_pattern(["command_line", "*nop" + LONG_SUFFIX])) == {patterned.lookalike.uuid}

    def test_values_within_one_entry_are_ored(self, patterned):
        found = _uuids(_pattern(["fqdn", "*.evil.com"], ["fqdn", "*.net"]))
        assert found == {patterned.subdomain.uuid, patterned.lookalike.uuid}

    def test_separate_entries_are_anded(self, patterned):
        both = _pattern(["fqdn", "*.net"]) + _pattern(["email_address", "*@evil.com"])
        assert _uuids(both) == {patterned.lookalike.uuid}
        assert _uuids(both + _pattern(["fqdn", "*.evil.com"])) == set()

    def test_inverted_keeps_alerts_with_no_observables_at_all(self, patterned):
        found = _uuids(_pattern(["fqdn", "*.evil.com"], inverted=True))
        assert patterned.plain.uuid in found and patterned.shouty.uuid in found
        assert patterned.subdomain.uuid not in found

    def test_a_pattern_that_matches_nothing(self, patterned):
        assert _uuids(_pattern(["fqdn", "*.not-there.example"])) == set()
        assert patterned.plain.uuid in _uuids(_pattern(["fqdn", "*.not-there.example"], inverted=True))

    def test_the_mapping_lookup_forces_its_primary_key(self, patterned):
        """Without the hint MySQL scans all of observable_mapping for the inverted form (3.7 s
        against 0.15 s at 5M rows); a test database is too small to show it in a plan."""
        for inverted in (False, True):
            query = build_alert_query(_pattern(["fqdn", "*.evil.com"], inverted=inverted), entity=Alert,
                                      tz=pytz.utc, locations=None)
            assert "observable_mapping FORCE INDEX (PRIMARY)" in str(query.statement.compile(dialect=get_db().bind.dialect))

    def test_count_alerts(self, patterned):
        assert count_alerts(_pattern(["fqdn", "*.evil.com"], ["fqdn", "*.net"]), entity=Alert, tz=pytz.utc,
                            locations=None) == 2

    def test_a_wildcard_at_both_ends_raises(self, patterned):
        """FilterEntry refuses it at write time; a filter list that never went through it (a
        caller of build_alert_query) must still not scan every observable."""
        with pytest.raises(ObservablePatternError, match="both ends"):
            _uuids(_pattern(["fqdn", "*evil*"]))

    def test_a_value_that_is_not_a_pair_raises(self, patterned):
        with pytest.raises(ObservablePatternError, match="pair"):
            _uuids([{"name": "Observable Pattern", "inverted": False, "values": ["*.evil.com"]}])

    def test_a_pattern_that_matches_too_many_observables_raises(self, patterned, monkeypatch):
        """Refused rather than cut short: a partial list of ids would silently drop alerts."""
        monkeypatch.setattr(filter_query, "MAX_PATTERN_OBSERVABLES", 1)
        with pytest.raises(ObservablePatternError, match="matches more than 1 observables;"):
            filter_query.resolve_observable_pattern(ANY_OBSERVABLE_TYPE, "*evil.com")
        with pytest.raises(ObservablePatternError):
            _uuids(_pattern([ANY_OBSERVABLE_TYPE, "*evil.com"]))

    def test_patterns_that_match_too_many_observables_together_raise(self, patterned, monkeypatch):
        monkeypatch.setattr(filter_query, "MAX_PATTERN_OBSERVABLES", 1)
        assert _uuids(_pattern(["fqdn", "*.net"])) == {patterned.lookalike.uuid}
        with pytest.raises(ObservablePatternError, match="together"):
            _uuids(_pattern(["fqdn", "*.net"], ["email_address", "*@evil.com"]))

    def test_a_lookup_that_runs_past_its_time_limit_raises(self, patterned, monkeypatch, caplog):
        """MySQL stops the statement (MAX_EXECUTION_TIME) with error 3024."""
        statements = []

        def execute(statement, *args, **kwargs):
            statements.append(str(statement.compile()))
            raise OperationalError("SELECT ...", {}, pymysql.err.OperationalError(
                3024, "Query execution was interrupted, maximum statement execution time exceeded"))

        monkeypatch.setattr(get_db(), "execute", execute)
        with pytest.raises(ObservablePatternError, match="took too long"):
            filter_query.resolve_observable_pattern("fqdn", "*.evil.com")
        assert f"MAX_EXECUTION_TIME({filter_query.PATTERN_LOOKUP_TIMEOUT_MS})" in statements[0]
        record = next(r for r in caplog.records if r.getMessage().startswith("observable pattern lookup stopped"))
        assert record.levelname == "INFO" and record.observable_pattern == "*.evil.com"

    def _time_out(self, monkeypatch) -> list:
        statements = []

        def execute(statement, *args, **kwargs):
            statements.append(statement)
            raise OperationalError("SELECT ...", {}, pymysql.err.OperationalError(
                3024, "Query execution was interrupted, maximum statement execution time exceeded"))

        monkeypatch.setattr(get_db(), "execute", execute)
        return statements

    def test_a_refused_pattern_is_not_looked_up_again_for_a_while(self, monkeypatch):
        """A pinned badge and an open manage page run their filter on every 30 second refresh;
        a lookup that runs to the time limit costs a second of MySQL each time."""
        statements = self._time_out(monkeypatch)
        for _ in range(3):
            with pytest.raises(ObservablePatternError, match="took too long"):
                filter_query.resolve_observable_pattern("user", "*.com")
        assert len(statements) == 1

        # only that pattern of that type
        with pytest.raises(ObservablePatternError):
            filter_query.resolve_observable_pattern("fqdn", "*.com")
        assert len(statements) == 2

    def test_a_refusal_expires(self, monkeypatch):
        """A lookup that timed out under load may not the next time."""
        monkeypatch.setattr(filter_query, "PATTERN_REFUSAL_TTL_SECONDS", 0)
        statements = self._time_out(monkeypatch)
        for _ in range(2):
            with pytest.raises(ObservablePatternError):
                filter_query.resolve_observable_pattern("user", "*.com")
        assert len(statements) == 2

    def test_a_pattern_over_the_cap_is_remembered_too(self, patterned, monkeypatch):
        monkeypatch.setattr(filter_query, "MAX_PATTERN_OBSERVABLES", 1)
        with pytest.raises(ObservablePatternError, match="matches more than 1"):
            filter_query.resolve_observable_pattern(ANY_OBSERVABLE_TYPE, "*evil.com")
        statements = self._time_out(monkeypatch)
        with pytest.raises(ObservablePatternError, match="matches more than 1"):
            filter_query.resolve_observable_pattern(ANY_OBSERVABLE_TYPE, "*evil.com")
        assert statements == []

    def test_a_pattern_that_was_looked_up_is_not_remembered(self, patterned):
        """Its observables can be added to at any time; only a refusal is remembered."""
        assert _uuids(_pattern(["fqdn", "*.evil.com"])) == {patterned.subdomain.uuid}
        later = insert_alert()
        attach_observable(later, "fqdn", "www.evil.com")
        assert _uuids(_pattern(["fqdn", "*.evil.com"])) == {patterned.subdomain.uuid, later.uuid}

    def test_a_real_time_limit_leaves_the_session_usable(self, patterned):
        """The error the hint raises is a statement error, not a broken connection or transaction:
        the page goes on to run its other queries on the same session."""
        db = get_db()
        a, b, c = (aliased(Observable) for _ in range(3))
        # SLEEP() alone is cut short without an error; a statement still reading rows when the
        # limit passes gets 3024. This one reads a few hundred rows, sleeping 1 ms on each.
        statement = select(func.count()).select_from(a).join(b, b.id >= a.id).join(c, c.id >= b.id) \
            .where(func.sleep(0.001) == 0).prefix_with("/*+ MAX_EXECUTION_TIME(5) */")
        with pytest.raises(OperationalError) as error:
            db.execute(statement)
        assert error.value.orig.args[0] == filter_query.ER_QUERY_TIMEOUT
        assert _uuids(_pattern(["fqdn", "*.evil.com"])) == {patterned.subdomain.uuid}

    def test_another_database_error_is_not_mistaken_for_a_time_limit(self, monkeypatch):
        def execute(statement, *args, **kwargs):
            raise OperationalError("SELECT ...", {}, pymysql.err.OperationalError(2013, "Lost connection"))

        monkeypatch.setattr(get_db(), "execute", execute)
        with pytest.raises(OperationalError):
            filter_query.resolve_observable_pattern("fqdn", "*.evil.com")


class TestOtherFilters:
    def test_tag(self, corpus):
        _, tagged, _ = corpus
        assert _uuids([{"name": "Tag", "inverted": False, "values": ["credential-harvest"]}]) == {tagged.uuid}

    def test_inverted_tag_keeps_untagged_alerts(self, corpus):
        signed, tagged, plain = corpus
        found = _uuids([{"name": "Tag", "inverted": True, "values": ["credential-harvest"]}])
        assert plain.uuid in found and signed.uuid in found and tagged.uuid not in found

    def test_queue(self, corpus):
        signed, _, _ = corpus
        assert _uuids([{"name": "Queue", "inverted": False, "values": ["external"]}]) == {signed.uuid}

    def test_date_range_resolves_in_the_timezone_it_is_given(self, corpus):
        """No current_user here: the caller supplies the timezone. `tagged` was inserted at
        2026-02-01 00:00 UTC, which is 19:00 on 01-31 in New York: inside a window that ends
        at 20:00 New York time, and outside one that ends at 20:00 UTC."""
        _, tagged, _ = corpus
        window = [{"name": "Alert Date", "inverted": False,
                   "values": ["01-15-2026 00:00 - 01-31-2026 20:00"]}]

        def uuids_in(tz):
            query = build_alert_query(window, entity=Alert, tz=tz, locations=None)
            return {row[0] for row in query.with_entities(Alert.uuid).distinct()}

        assert uuids_in(pytz.timezone("America/New_York")) == {tagged.uuid}
        assert uuids_in(pytz.utc) == set()


class TestHelpers:
    def test_filter_alert_uuids_preserves_order_and_drops_the_rest(self, corpus):
        signed, tagged, plain = corpus
        given = [plain.uuid, signed.uuid, tagged.uuid]
        kept = filter_alert_uuids(
            [{"name": "Observable", "inverted": True, "values": [["ipv4", "10.20.30.40"]]}],
            given, entity=Alert, tz=pytz.utc, locations=None)
        assert kept == [plain.uuid, tagged.uuid]

    def test_filter_alert_uuids_with_nothing_given(self):
        assert filter_alert_uuids([], [], entity=Alert, tz=pytz.utc, locations=None) == []


class TestAliasedEntity:
    """The mapping-table filters correlate their EXISTS to the entity the outer query selects.
    They used to name `Alert`, which only worked because every caller selected `Alert` itself
    or `GUIAlert` on the same table: against an alias, the subquery stopped correlating and
    matched every alert as soon as any alert matched."""

    @staticmethod
    def _aliased_uuids(filters):
        from sqlalchemy.orm import aliased

        entity = aliased(Alert)
        query = build_alert_query(filters, entity=entity, tz=pytz.utc, locations=None)
        return {row[0] for row in query.with_entities(entity.uuid).distinct()}

    def test_tag(self, corpus):
        signed, tagged, plain = corpus
        assert self._aliased_uuids([{"name": "Tag", "inverted": False, "values": ["credential-harvest"]}]) == {tagged.uuid}
        inverted = self._aliased_uuids([{"name": "Tag", "inverted": True, "values": ["credential-harvest"]}])
        assert plain.uuid in inverted and signed.uuid in inverted and tagged.uuid not in inverted

    def test_observable(self, corpus):
        signed, _, _ = corpus
        assert self._aliased_uuids([{"name": "Observable", "inverted": False,
                                     "values": [["signature_id", SIGNATURE_UUID]]}]) == {signed.uuid}

    def test_detection_point(self, detections):
        v1, v2, _, _ = detections
        assert self._aliased_uuids(_detection_filter(SIGNATURE_UUID)) == {v1.uuid, v2.uuid}

    def test_observable_pattern(self, patterned):
        assert self._aliased_uuids(_pattern(["fqdn", "*.evil.com"])) == {patterned.subdomain.uuid}
        assert patterned.subdomain.uuid not in self._aliased_uuids(_pattern(["fqdn", "*.evil.com"], inverted=True))

    def test_analysis(self, analyzed):
        qr, qr_and_urls, _, _ = analyzed
        assert self._aliased_uuids(_analysis_filter(QR_CODE_ANALYSIS)) == {qr.uuid, qr_and_urls.uuid}

    def test_unconfirmed_detections(self):
        detections = [{"description": "a", "signature_uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
                      {"description": "b", "signature_uuid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}]
        unconfirmed = insert_alert_with_detections(detections, disposition="DELIVERY")
        single = insert_alert_with_detections(detections[:1], disposition="DELIVERY")

        entry = {"name": "Unconfirmed Detections", "inverted": False, "values": ["True"]}
        assert self._aliased_uuids([entry]) == {unconfirmed.uuid}
        assert _uuids([entry]) == {unconfirmed.uuid}
        assert single.uuid in self._aliased_uuids([dict(entry, values=["False"])])
