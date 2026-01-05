import logging
import os
import re
import shutil
import signal
from subprocess import PIPE, Popen
import pytest

from saq.collectors.base_collector import CollectorExecutionMode
from saq.collectors.email.scanner import EmailCollectorService
from saq.configuration.config import get_config, get_service_config
from saq.configuration.schema import CollectionGroupConfig
from saq.constants import ANALYSIS_MODE_EMAIL, SERVICE_EMAIL_COLLECTOR
from saq.database.pool import get_db_connection
from saq.engine.core import Engine
from saq.engine.engine_configuration import EngineConfiguration
from saq.environment import get_base_dir, get_data_dir
from tests.saq.helpers import log_count, search_log, search_log_regex, wait_for_log_count, wait_for_process

@pytest.fixture(autouse=True, scope="function")
def setup(monkeypatch):
    os.makedirs(get_email_dir(), exist_ok=True)


@pytest.mark.integration
def test_startup():
    collector = EmailCollectorService()
    collector.load_groups()
    collector.start_single_threaded(execution_mode=CollectorExecutionMode.SINGLE_SHOT)
    assert log_count('no work available') == 1

def get_email_dir() -> str:
    return os.path.join(get_data_dir(), get_config().email.email_dir)

def submit_email(email_path: str):
    amc_mda_path = os.path.join(get_base_dir(), 'bin', 'amc_mda')

    process = Popen(
            ['python3', amc_mda_path, '--base-dir', get_base_dir(), '--data-dir', get_email_dir()], 
            stdin=PIPE,
            stdout=PIPE,
            stderr=PIPE)

    try:
        with open(email_path, 'rb') as fp:
            shutil.copyfileobj(fp, process.stdin)
    except Exception as e:
        logging.error("write to amc failed: %s", e)

    _stdout, _stderr = process.communicate()
    if _stdout:
        logging.debug(f"submit_email: {_stdout}")

    if _stderr:
        logging.error("submit_email: {_stderr}")

@pytest.mark.integration
def test_single_email(datadir):
    submit_email(str(datadir / 'pdf_attachment.email.rfc822'))

    collector = EmailCollectorService()
    collector.load_groups()
    collector.start_single_threaded(execution_mode=CollectorExecutionMode.SINGLE_SHOT)

    assert log_count('found email') == 1

@pytest.mark.integration
def test_multiple_emails(datadir):
    test_email_dir = str(datadir / "emails")
    email_count = 0
    for email_file in os.listdir(test_email_dir):
        email_count += 1
        submit_email(os.path.join(test_email_dir, email_file))

    collector = EmailCollectorService()
    collector.load_groups()
    collector.start_single_threaded(execution_mode=CollectorExecutionMode.SINGLE_SHOT)
    assert log_count('found email') == email_count

@pytest.mark.integration
def test_blacklist(tmpdir, datadir):
    blacklist_yara_rule_path = str(tmpdir / "blacklist.yar")
    with open(blacklist_yara_rule_path, 'w') as fp:
        fp.write("""
rule blacklist : blacklist {
    strings:
        $a = "Message-ID: <80f00181-6bb3-45ee-a16d-b2b25df6cf1e@journal.report.generator>"
    condition:
        any of them
}""")

    submit_email(str(datadir / 'pdf_attachment.email.rfc822'))

    get_service_config(SERVICE_EMAIL_COLLECTOR).blacklist_yara_rule_path = blacklist_yara_rule_path
    collector = EmailCollectorService()
    collector.load_groups()
    collector.start_single_threaded(execution_mode=CollectorExecutionMode.SINGLE_SHOT)

    assert log_count('matched blacklist rule') == 1

    # the file that we matched should be deleted
    entry = search_log('matched blacklist rule')
    assert len(entry) == 1
    entry = entry[0]
    regex = re.compile(r'^(.+) matched blacklist rule .+')
    match_result = regex.match(entry.getMessage())
    assert match_result
    file_path = match_result.group(1)
    assert not os.path.exists(file_path)

@pytest.mark.integration
def test_assignment(tmpdir, datadir):
    assignment_yara_rule_path = str(tmpdir / "assignment.yar")
    with open(assignment_yara_rule_path, 'w') as fp:
        fp.write("""
rule assignment: unittest {
    strings:
        $a = "Delivered-To: company@mail.phish.solutions"
    condition:
        any of them
}""")
    submit_email(str(datadir / 'pdf_attachment.email.rfc822'))

    # we add another node group for testing purposes
    get_config().add_collection_group_config('qa', CollectionGroupConfig(name='qa', enabled=True, coverage=100, full_delivery=False, database='ace', company_id=1))
    get_service_config(SERVICE_EMAIL_COLLECTOR).assignment_yara_rule_path = assignment_yara_rule_path
    collector = EmailCollectorService()
    collector.load_groups()
    collector.start_single_threaded(execution_mode=CollectorExecutionMode.SINGLE_SHOT)

    # look for all the expected log entries
    assert log_count('found email') == 1
    assert log_count('scheduled ACE Mailbox Scanner Detection -') == 1

    # assigning email /opt/ace/data_unittest/var/incoming/amc/2026010421/3ddcedc4-b314-4f5b-a751-4ea04ad32cc0 to groups unittest
    assert search_log_regex(re.compile(r'^assigning email (.+) to groups unittest$'))

    # assigning 1596 to remote node group RemoteNodeGroup(name=unittest, coverage=100, full_delivery=True, company_id=1, database=ace)
    assert search_log_regex(re.compile(r'^assigning \d+ to remote node group RemoteNodeGroup\(name=unittest, coverage=100, full_delivery=True, company_id=1, database=ace\)'))

@pytest.mark.system
def test_complete_processing(datadir):
    submit_email(str(datadir / 'pdf_attachment.email.rfc822'))

    engine = Engine(config=EngineConfiguration(pool_size_limit=1, local_analysis_modes=[ANALYSIS_MODE_EMAIL]))
    engine.configuration_manager.enable_module('file_type')
    engine.configuration_manager.enable_module('email_analyzer')
    engine_process = engine.start_nonblocking()
    engine.wait_for_start()

    collector = EmailCollectorService()
    collector.load_groups()
    collector.start()
    assert collector.wait_for_start()

    # look for all the expected log entries
    wait_for_log_count('found email', 1, 5)
    #wait_for_log_count('moved file from', 1, 5)
    # email analysis module should generate this log entry
    wait_for_log_count('parsing email file', 1, 5)
    wait_for_log_count('scheduled ACE Mailbox Scanner Detection -', 1, 5)
    wait_for_log_count('completed analysis RootAnalysis', 1, 20)

    assert engine_process.pid
    os.kill(engine_process.pid, signal.SIGTERM)
    wait_for_process(engine_process)

    collector.stop()
    collector.wait()

@pytest.mark.system
def test_multiple_emails_complete_processing(datadir):
    test_email_dir = str(datadir / 'emails')
    email_count = 0
    for email_file in os.listdir(test_email_dir):
        email_count += 1
        submit_email(os.path.join(test_email_dir, email_file))

    engine = Engine(config=EngineConfiguration(pool_size_limit=1, local_analysis_modes=[ANALYSIS_MODE_EMAIL]))
    engine.configuration_manager.enable_module('file_type')
    engine.configuration_manager.enable_module('email_analyzer')
    engine_process = engine.start_nonblocking()
    engine.wait_for_start()

    collector = EmailCollectorService()
    collector.load_groups()
    collector.start()
    assert collector.wait_for_start()

    # look for all the expected log entries
    wait_for_log_count('found email', email_count, 5)
    #wait_for_log_count('moved file from', email_count, 5)
    wait_for_log_count('scheduled ACE Mailbox Scanner Detection -', email_count, 5)
    wait_for_log_count('completed analysis RootAnalysis', email_count, 20)

    assert engine_process.pid
    os.kill(engine_process.pid, signal.SIGTERM)
    wait_for_process(engine_process)

    collector.stop()
    collector.wait()