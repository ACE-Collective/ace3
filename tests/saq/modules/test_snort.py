# vim: sw=4:ts=4:et:cc=120

from saq.constants import *

from saq.modules.snort import (
        build_signature_db,
        extract_signature,
        is_signature_db_stale,
        lock_signature_db,
        AlreadyLockedException,
        KEY_SURICATA_RULES_MTIME,
        KEY_SURICATA_RULES_LOCK,)

import logging

import fakeredis
import pytest
import redis

from saq.analysis.root import load_root
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.snort import SnortSignatureAnalysis_v1
from saq.util.uuid import get_storage_dir

rule_1 = """alert ip $HOME_NET any -> [109.196.130.50,151.13.184.200] any (msg:"ET CNC Shadowserver Reported CnC Server IP group 1"; reference:url,doc.emergingthreats.net/bin/view/Main/BotCC; reference:url,www.shadowserver.org; threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404000; rev:5818; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag Shadowserver, signature_severity Major, created_at 2012_05_04, updated_at 2020_08_07;)"""
rule_2 = """alert ip $HOME_NET any -> [154.35.64.107,154.35.64.18] any (msg:"ET CNC Shadowserver Reported CnC Server IP group 2"; reference:url,doc.emergingthreats.net/bin/view/Main/BotCC; reference:url,www.shadowserver.org; threshold: type limit, track by_src, seconds 3600, count 1; flowbits:set,ET.Evil; flowbits:set,ET.BotccIP; classtype:trojan-activity; sid:2404001; rev:5818; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag Shadowserver, signature_severity Major, created_at 2012_05_04, updated_at 2020_08_07;)"""
rule_data = '\n'.join([rule_1, rule_2])

@pytest.fixture(scope="function")
def redis_connection():
    return fakeredis.FakeStrictRedis(decode_responses=True, encoding='utf-8')

@pytest.fixture
def sig_path(tmp_path):
    result = str(tmp_path / 'temp.rules')
    with open(result, 'w') as fp:
        fp.write(rule_data)

    return result

@pytest.fixture
def sig_db(sig_path, redis_connection):
    return build_signature_db(sig_path, get_redis_connection=lambda: redis_connection)

@pytest.mark.unit
def test_refused_lock_leaves_the_holder_locked(sig_db):
    with lock_signature_db(get_redis_connection=lambda: sig_db) as lock_uuid:
        with pytest.raises(AlreadyLockedException):
            with lock_signature_db(get_redis_connection=lambda: sig_db):
                pass

        # the refused rebuild must not have released the lock of the one still running
        assert sig_db[KEY_SURICATA_RULES_LOCK] == lock_uuid
        assert build_signature_db("/nonexistent.rules", get_redis_connection=lambda: sig_db) is False

    assert KEY_SURICATA_RULES_LOCK not in sig_db

@pytest.mark.unit
def test_expired_lock_is_not_released(sig_db):
    with lock_signature_db(get_redis_connection=lambda: sig_db):
        # the lock expired during a long rebuild and another one took it
        sig_db.set(KEY_SURICATA_RULES_LOCK, "other rebuild")

    assert sig_db[KEY_SURICATA_RULES_LOCK] == "other rebuild"

@pytest.mark.unit
def test_build_signature_db_skips_lines_without_sid_and_rev(tmp_path, redis_connection):
    path = tmp_path / "mixed.rules"
    path.write_text("# a comment\n" + rule_1 + "\nalert ip any any -> any any (msg:\"no sid\";)\n")

    assert build_signature_db(str(path), get_redis_connection=lambda: redis_connection)
    assert [key for key in redis_connection.keys() if key != KEY_SURICATA_RULES_MTIME] == [
        # "<sid>:<rev>": the index outlives a release, so its key layout is fixed
        "2404000:5818"]

@pytest.mark.unit
def test_extract_signature_with_redis_unavailable():
    class Unavailable:
        def get(self, key):
            raise ConnectionError("redis is down")

    with pytest.raises(ConnectionError):
        extract_signature('2404000', '5818', get_redis_connection=Unavailable)


def _analyze(root_analysis, monkeypatch, sig_db, value):
    monkeypatch.setattr("saq.modules.snort.extract_signature",
        lambda signature_id, rev: extract_signature(signature_id, rev, get_redis_connection=lambda: sig_db))

    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_SNORT_SIGNATURE, value)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("snort_signature_analysis_v1", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.SINGLE_SHOT)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    analysis = root_analysis.get_observable(observable.uuid).get_and_load_analysis(SnortSignatureAnalysis_v1)
    return root_analysis, analysis

@pytest.mark.integration
def test_snort_signature_analyzer(root_analysis, monkeypatch, sig_db):
    root_analysis, analysis = _analyze(root_analysis, monkeypatch, sig_db, "1:2404000:5818")

    assert analysis.signature_id == "2404000 rev 5818"
    assert analysis.signature == rule_1
    assert analysis.generate_summary() == f"Signature Analysis - (2404000 rev 5818) {rule_1}"
    assert analysis.jinja_is_drillable is False
    assert [(detail.header, detail.content) for detail in root_analysis.summary_details] == [
        ("Suricata Signature 2404000 rev 5818", rule_1)]

@pytest.mark.integration
def test_snort_signature_analyzer_unknown_signature(root_analysis, monkeypatch, sig_db, caplog):
    root_analysis, analysis = _analyze(root_analysis, monkeypatch, sig_db, "1:2404999:1")

    assert "cannot find snort signature 2404999 rev 1" in caplog.text
    assert analysis.signature_id is None
    assert analysis.generate_summary() is None
    assert not root_analysis.summary_details

@pytest.mark.integration
def test_snort_signature_analyzer_redis_unavailable(root_analysis, monkeypatch, caplog):
    class Unavailable:
        def get(self, key):
            raise ConnectionError("redis is down")

    root_analysis, analysis = _analyze(root_analysis, monkeypatch, Unavailable(), "1:2404000:5818")

    assert "redis for snort signature 2404000 rev 5818 unavailable: redis is down" in caplog.text
    assert analysis.error == "unable to look up the signature: redis is down"
    assert analysis.signature_id is None

@pytest.mark.integration
def test_snort_signature_analyzer_redis_client_connection_error_is_an_outage(root_analysis, monkeypatch, caplog):
    class Unavailable:
        def get(self, key):
            raise redis.exceptions.ConnectionError("connection refused")

    root_analysis, analysis = _analyze(root_analysis, monkeypatch, Unavailable(), "1:2404000:5818")

    assert "redis for snort signature 2404000 rev 5818 unavailable: connection refused" in caplog.text
    assert not [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert analysis.error == "unable to look up the signature: connection refused"

@pytest.mark.integration
def test_snort_signature_analyzer_redis_error_is_logged_with_traceback(root_analysis, monkeypatch, caplog):
    class WrongType:
        def get(self, key):
            raise redis.exceptions.ResponseError("WRONGTYPE Operation against a key holding the wrong kind of value")

    root_analysis, analysis = _analyze(root_analysis, monkeypatch, WrongType(), "1:2404000:5818")

    [record] = [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert record.getMessage() == "unable to look up snort signature 2404000 rev 5818"
    assert record.exc_info is not None
    assert record.root_uuid == root_analysis.uuid
    assert analysis.error == "unable to look up the signature: WRONGTYPE Operation against a key holding the wrong kind of value"

@pytest.mark.integration
def test_snort_signature_analyzer_unparsable_value(root_analysis, monkeypatch, sig_db, caplog):
    root_analysis, analysis = _analyze(root_analysis, monkeypatch, sig_db, "2404000")

    assert "missing signature_id or ref in 2404000" in caplog.text
    assert analysis.signature_id is None
    assert analysis.generate_summary() is None
