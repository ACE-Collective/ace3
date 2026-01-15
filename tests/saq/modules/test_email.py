from datetime import datetime
import filecmp
import gzip
import json
import os
import shutil
import pytest
import pytz

from saq.analysis.root import RootAnalysis, load_root
from saq.configuration.config import get_config, get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_EMAIL_LOGGER, ANALYSIS_TYPE_BRO_SMTP, ANALYSIS_TYPE_MAILBOX, DB_BROCESS, DB_EMAIL_ARCHIVE, DIRECTIVE_ARCHIVE, DIRECTIVE_EXTRACT_URLS, DIRECTIVE_ORIGINAL_EMAIL, DIRECTIVE_PREVIEW, DIRECTIVE_REMEDIATE, DIRECTIVE_RENAME_ANALYSIS, EVENT_TIME_FORMAT_JSON_TZ, F_EMAIL_ADDRESS, F_EMAIL_CONVERSATION, F_EMAIL_DELIVERY, F_FILE, F_MESSAGE_ID, F_URL, create_email_conversation, create_email_delivery
from saq.crypto import decrypt
from saq.database.model import load_alert
from saq.database.pool import get_db_connection
from saq.email import normalize_email_address
from saq.engine.core import Engine
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineExecutionMode
from saq.environment import get_data_dir, get_global_runtime_settings, get_local_timezone, get_temp_dir
from saq.json_encoding import _JSONEncoder
from saq.modules.email.archive import EmailArchiveResults
from saq.modules.email.correlation import URLEmailPivotAnalysis_v2
from saq.modules.email.logging import EmailLoggingAnalyzer
from saq.modules.email.mailbox import MAILBOX_ALERT_PREFIX
from saq.modules.email.message_id import MessageIDAnalysisV2
from saq.modules.email.rfc822 import EmailAnalysis
from saq.util.hashing import sha256_file
from saq.util.uuid import get_storage_dir
from tests.saq.helpers import create_root_analysis


@pytest.mark.integration
def test_mailbox(root_analysis, datadir):
    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.details = { 'hello': 'world' }
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/splunk_logging.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('mailbox_email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    
    # we should still have our old details
    assert 'hello' in root_analysis.details
    # merged in with our email analysis
    assert 'email' in root_analysis.details
    assert root_analysis.details['email']
    assert root_analysis.description.startswith(MAILBOX_ALERT_PREFIX)

@pytest.mark.integration
def test_no_mailbox(root_analysis, datadir):
    # make sure that when we analyze emails in non-mailbox analysis that we don't treat it like it came from mailbox
    root_analysis.alert_type = "not-mailbox" # <-- different alert_type
    root_analysis.details = { 'hello': 'world' }
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/splunk_logging.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('mailbox_email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    
    # we should still have our old details
    assert 'hello' in root_analysis.details
    # and we should NOT have the email details merged in since it's not a mailbox analysis
    assert 'email' not in root_analysis.details

@pytest.mark.integration
def test_mailbox_whitelisted(root_analysis, datadir):
    # make sure that we do not process whitelisted emails
    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.details = { 'hello': 'world' }
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/splunk_logging.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    file_observable.whitelist()
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('mailbox_email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    
    # we should still have our old details
    assert 'hello' in root_analysis.details
    # and we should NOT have the email details merged in since it's not a mailbox analysis
    assert 'email' not in root_analysis.details
    # and we should be whitelisted at this point
    assert root_analysis.whitelisted

@pytest.mark.integration
def test_mailbox_submission(test_client, root_analysis, datadir):
    from flask import url_for
    from saq.modules.email import EmailAnalysis

    event_time = get_local_timezone().localize(datetime.now()).astimezone(pytz.UTC).strftime(EVENT_TIME_FORMAT_JSON_TZ)
    sha256 = sha256_file(str(datadir / 'emails/splunk_logging.email.rfc822'))
    with open(str(datadir / 'emails/splunk_logging.email.rfc822'), 'rb') as fp:
        result = test_client.post(url_for('analysis.submit'), data={
            'analysis': json.dumps({
                'analysis_mode': 'email',
                'tool': 'unittest',
                'tool_instance': 'unittest_instance',
                'type': 'mailbox',
                'description': 'testing',
                'event_time': event_time,
                'details': { },
                'observables': [
                    { 'type': F_FILE, 'value': sha256, 'file_path': 'rfc822.email', 'time': event_time, 'tags': [], 'directives': [ DIRECTIVE_ORIGINAL_EMAIL ], 'limited_analysis': [] },
                ],
                'tags': [ ],
            }, cls=_JSONEncoder),
            'file': (fp, 'rfc822.email'),
            }, content_type='multipart/form-data', headers = { 'x-ice-auth': get_config().api.api_key })

    result = result.get_json()
    assert result

    assert 'result' in result
    result = result['result']
    assert result['uuid']
    uuid = result['uuid']

    # make sure we don't clean up the anaysis so we can check it
    get_config().get_analysis_mode_config('email').cleanup = False

    engine = Engine(config=EngineConfiguration(local_analysis_modes=['email']))
    engine.configuration_manager.enable_module('file_type', 'email')
    engine.configuration_manager.enable_module('email_analyzer', 'email')
    engine.configuration_manager.enable_module('mailbox_email_analyzer', 'email')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = RootAnalysis(storage_dir=get_storage_dir(uuid))
    root_analysis.load()

    observable = root_analysis.find_observable(lambda o: o.has_directive(DIRECTIVE_ORIGINAL_EMAIL))
    assert observable
    analysis = observable.get_and_load_analysis(EmailAnalysis)
    assert isinstance(analysis, EmailAnalysis)
    assert analysis.load_details()

    # these should be the same
    assert analysis.details == root_analysis.details

@pytest.mark.integration
def test_splunk_logging(root_analysis, datadir, monkeypatch):

    # enable splunk logging
    monkeypatch.setattr(get_analysis_module_config(ANALYSIS_MODULE_EMAIL_LOGGER), 'splunk_log_enabled', True)

    # clear splunk logging directory
    splunk_log_dir = os.path.join(get_data_dir(), get_config().splunk_logging.splunk_log_dir, 'smtp')
    if os.path.isdir(splunk_log_dir):
        shutil.rmtree(splunk_log_dir)
        os.mkdir(splunk_log_dir)

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/splunk_logging.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('email_logger', 'test_groups')
    engine.configuration_manager.enable_module('url_extraction', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # we should expect three files in this directory now
    splunk_files = os.listdir(splunk_log_dir)
    assert len(splunk_files) == 3
    
    smtp_file = None
    url_file = None
    fields_file = None

    for _file in splunk_files:
        if _file.startswith('smtp-'):
            smtp_file = os.path.join(splunk_log_dir, _file)
        elif _file.startswith('url-'):
            url_file = os.path.join(splunk_log_dir, _file)
        elif _file == 'fields':
            fields_file = os.path.join(splunk_log_dir, _file)

    assert smtp_file
    assert url_file
    assert fields_file

    with open(smtp_file, 'r') as fp:
        smtp_logs = fp.read()

    with open(url_file, 'r') as fp:
        url_logs = fp.read()

    smtp_logs = [_ for _ in smtp_logs.split('\n') if _]
    url_logs = [_ for _ in url_logs.split('\n') if _]

    assert len(smtp_logs) == 1
    assert len(url_logs) == 2

    url_fields = url_logs[0].split('\x1e')
    assert len(url_fields) == 3

    smtp_fields = smtp_logs[0].split('\x1e')
    assert len(smtp_fields) == 25
    
    with open(fields_file, 'r') as fp:
        fields = fp.readline().strip()

    assert fields == ('date,attachment_count,attachment_hashes,attachment_names,attachment_sizes,attachment_types,bcc,'
                                'cc,env_mail_from,env_rcpt_to,extracted_urls,first_received,headers,last_received,mail_from,'
                                'mail_to,message_id,originating_ip,path,reply_to,size,subject,user_agent,archive_path,x_mailer')

@pytest.mark.integration
def test_update_brocess(root_analysis, datadir):

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/splunk_logging.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('email_logger', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))

    file_observable = root_analysis.get_observable(file_observable.uuid)
    from saq.modules.email import EmailAnalysis
    analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    assert isinstance(analysis, EmailAnalysis)
    analysis.load_details()

    # get the source and dest of the email so we can look it up in the brocess database

    mail_from = normalize_email_address(analysis.mail_from)
    env_rcpt_to = normalize_email_address(analysis.env_rcpt_to[0])

    # we should see a count of 1 here

    with get_db_connection(DB_BROCESS) as db:
        cursor = db.cursor()
        cursor.execute("""SELECT numconnections FROM smtplog WHERE source = %s AND destination = %s""",
                    (mail_from, env_rcpt_to))
        count = cursor.fetchone()
        assert count[0] == 1

    # and then we do it again and make sure the count increased

    root_analysis = create_root_analysis(alert_type=ANALYSIS_TYPE_MAILBOX, analysis_mode="test_groups")
    root_analysis.initialize_storage()
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/splunk_logging.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('email_logger', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    with get_db_connection(DB_BROCESS) as db:
        cursor = db.cursor()
        cursor.execute("""SELECT numconnections FROM smtplog WHERE source = %s AND destination = %s""",
                    (mail_from, env_rcpt_to))
        count = cursor.fetchone()
        assert count[0] == 2

@pytest.mark.skip()
@pytest.mark.integration
def test_archive_1(root_analysis, datadir):

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/splunk_logging.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ARCHIVE)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('file_hash_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('email_archiver', 'test_groups')
    engine.configuration_manager.enable_module('url_extraction', 'test_groups')
    engine.configuration_manager.enable_module('parse_url', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))

    file_observable = root_analysis.get_observable(file_observable.uuid)
    assert file_observable
    archive_results = file_observable.get_and_load_analysis('EmailArchiveResults')
    assert isinstance(archive_results, EmailArchiveResults)
    archive_results.load_details()
    
    # this should point to the archive file (minus the .e at the end)
    assert os.path.exists(archive_results.archive_path)

    # make sure we can decrypt it
    gzip_path = os.path.join(get_temp_dir(), 'temp.gz')
    dest_path = os.path.join(get_temp_dir(), 'temp.email')

    decrypt(archive_results.archive_path, gzip_path)
    with gzip.open(gzip_path, 'rb') as fp_in:
        with open(dest_path, 'wb') as fp_out:
            shutil.copyfileobj(fp_in, fp_out)

    # this should be the same as the original email
    assert filecmp.cmp(dest_path, file_observable.full_path)

    # there should be a single entry in the archive
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT archive_id FROM archive")
        row = cursor.fetchone()
        assert row
        archive_id = row[0]

        message_id = '<CANTOGZsMiMb+7aB868zXSen_fO=NS-qFTUMo9h2eHtOexY8Qhw@mail.gmail.com>'

        cursor.execute("SELECT * FROM email_history WHERE message_id_hash = UNHEX(SHA2(%s, 256))", (message_id,))
        row = cursor.fetchone()
        assert row

@pytest.mark.skip()
@pytest.mark.integration
def test_archive_extraction(mock_api_call, root_analysis, datadir):

    # when we have the email already analyzed we don't need to extract it from the archives

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/pdf_attachment.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ARCHIVE)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('file_hash_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('email_archiver', 'test_groups')
    engine.configuration_manager.enable_module('message_id_analyzer_v2', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))

    file_observable = root_analysis.get_observable(file_observable.uuid)
    assert file_observable
    archive_results = file_observable.get_and_load_analysis('EmailArchiveResults')
    assert isinstance(archive_results, EmailArchiveResults)
    email_analysis = file_observable.get_and_load_analysis('EmailAnalysis')
    assert isinstance(email_analysis, EmailAnalysis)
    message_id_observable = email_analysis.get_observables_by_type(F_MESSAGE_ID)[0]
    assert message_id_observable
    assert not message_id_observable.get_and_load_analysis('MessageIDAnalysisV2')

    # but now that the email is archived we should be able to pull it out if we only have the message id
    root_analysis = create_root_analysis(analysis_mode="test_groups")
    root_analysis.initialize_storage()
    message_id_observable = root_analysis.add_observable_by_spec(F_MESSAGE_ID, message_id_observable.value)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('message_id_analyzer_v2', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))

    message_id_observable = root_analysis.get_observable(message_id_observable.uuid)
    assert message_id_observable
    message_id_analysis = message_id_observable.get_and_load_analysis('MessageIDAnalysisV2')
    assert isinstance(message_id_analysis, MessageIDAnalysisV2)
    # should have the encrypted email attached as a file
    assert len(message_id_analysis.get_observables_by_type(F_FILE)) == 1

@pytest.mark.skip()
@pytest.mark.integration
def test_archive_2(root_analysis, datadir):

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/pdf_attachment.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ARCHIVE)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('file_hash_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('email_archiver', 'test_groups')
    engine.configuration_manager.enable_module('url_extraction', 'test_groups')
    engine.configuration_manager.enable_module('pdf_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))

    file_observable = root_analysis.get_observable(file_observable.uuid)
    assert file_observable
    archive_results = file_observable.get_and_load_analysis('EmailArchiveResults')
    assert isinstance(archive_results, EmailArchiveResults)
    archive_results.load_details()
    # this should point to the archive file (minus the .e at the end)
    assert archive_results.archive_path
    assert os.path.exists(archive_results.archive_path)

    # make sure we can decrypt it
    gzip_path = os.path.join(get_temp_dir(), 'temp.gz')
    dest_path = os.path.join(get_temp_dir(), 'temp.email')

    decrypt(archive_results.archive_path, gzip_path)
    with gzip.open(gzip_path, 'rb') as fp_in:
        with open(dest_path, 'wb') as fp_out:
            shutil.copyfileobj(fp_in, fp_out)

    # this should be the same as the original email
    assert filecmp.cmp(dest_path, file_observable.full_path)

    # there should be a single entry in the archive
    with get_db_connection(DB_EMAIL_ARCHIVE) as db:
        cursor = db.cursor()
        cursor.execute("SELECT archive_id FROM archive")
        row = cursor.fetchone()
        archive_id = row[0]

        message_id = '<CANTOGZuWahvYOEr0NwPELF5ASriGNWjfVsWhMSE_ekiSVw1RbA@mail.gmail.com>'
        cursor.execute("SELECT * FROM email_history WHERE message_id_hash = UNHEX(SHA2(%s, 256))", (message_id,))
        row = cursor.fetchone()
        assert row

@pytest.mark.skip()
@pytest.mark.integration
def test_archive_no_local_archive(root_analysis, monkeypatch, datadir):

    # disable archive encryption
    monkeypatch.setattr(get_global_runtime_settings(), "encryption_key", None)

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/splunk_logging.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ARCHIVE)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('file_hash_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('email_archiver', 'test_groups')
    engine.configuration_manager.enable_module('url_extraction', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))

    file_observable = root_analysis.get_observable(file_observable.uuid)
    assert file_observable
    archive_results = file_observable.get_and_load_analysis(EmailArchiveResults)
    assert isinstance(archive_results, EmailArchiveResults)
    archive_results.load_details()
    
    # the details is typicaly the path to the archive but will be None here since it's disabled
    assert archive_results.archive_id is None

@pytest.mark.integration
def test_email_pivot(root_analysis, datadir):

    # process the email first -- we'll find it when we pivot

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/splunk_logging.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    file_observable.add_directive(DIRECTIVE_ARCHIVE)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('file_hash_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('email_archiver', 'test_groups')
    engine.configuration_manager.enable_module('url_extraction', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    new_root = create_root_analysis(analysis_mode="test_groups")
    new_root.initialize_storage()

    # make up some details
    new_root.details = { 
        'alertable': 1,
        'context': {
            'c': '1c38af75-0c42-4ae3-941d-de3975f68602',
            'd': '1',
            'i': 'ashland',
            's': 'email_scanner'
        },
        'sha256_url': '0061537d578e4f65d13e31e190e1079e00dadd808e9fa73f77e3308fdb0e1485',
        'url': 'https://www.alienvault.com', # <-- the important part
    }

    url_observable = new_root.add_observable_by_spec(F_URL, 'https://www.alienvault.com')
    new_root.save()
    new_root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('url_email_pivot_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    new_root = load_root(get_storage_dir(new_root.uuid))
    url_observable = new_root.get_observable(url_observable.uuid)
    analysis = url_observable.get_and_load_analysis(URLEmailPivotAnalysis_v2)
    assert isinstance(analysis, URLEmailPivotAnalysis_v2)
    analysis.load_details()
    assert analysis.count == 1

@pytest.mark.integration
def test_email_pivot_excessive_emails(root_analysis, datadir):

    # process the email first -- we'll find it when we pivot

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/splunk_logging.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    file_observable.add_directive(DIRECTIVE_ARCHIVE)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('file_hash_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('email_archiver', 'test_groups')
    engine.configuration_manager.enable_module('url_extraction', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    # force this to exceed the limit
    get_analysis_module_config('url_email_pivot_analyzer').result_limit = 0
    new_root = create_root_analysis(analysis_mode="test_groups")
    new_root.initialize_storage()

    # make up some details
    new_root.details = { 
        'alertable': 1,
        'context': {
            'c': '1c38af75-0c42-4ae3-941d-de3975f68602',
            'd': '1',
            'i': 'ashland',
            's': 'email_scanner'
        },
        'sha256_url': '0061537d578e4f65d13e31e190e1079e00dadd808e9fa73f77e3308fdb0e1485',
        'url': 'https://www.alienvault.com', # <-- the important part
    }

    url_observable = new_root.add_observable_by_spec(F_URL, 'https://www.alienvault.com')
    new_root.save()
    new_root.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('url_email_pivot_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    new_root = load_root(get_storage_dir(new_root.uuid))
    url_observable = new_root.get_observable(url_observable.uuid)
    analysis = url_observable.get_and_load_analysis(URLEmailPivotAnalysis_v2)
    assert isinstance(analysis, URLEmailPivotAnalysis_v2)
    analysis.load_details()
    assert analysis.count == 1
    # this should not have the details since it exceeded the limit
    assert analysis.emails is None

@pytest.mark.integration
def test_message_id(root_analysis, datadir):

    # make sure we extract the correct message-id
    # this test email has an attachment that contains a message-id
    # we need to make sure we do not extract that one as the message-id observable

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/extra_message_id.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))

    file_observable = root_analysis.get_observable(file_observable.uuid)
    assert file_observable
    email_analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    assert isinstance(email_analysis, EmailAnalysis)
    message_id = email_analysis.get_observables_by_type(F_MESSAGE_ID)
    assert isinstance(message_id, list) and len(message_id) > 0
    message_id = message_id[0]
    
    assert message_id.value == "<MW2PR16MB224997B938FB40AA00214DACA8590@MW2PR16MB2249.namprd16.prod.outlook.com>"

@pytest.mark.integration
def test_basic_email_parsing(root_analysis, datadir):

    # parse a basic email message

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/splunk_logging.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    
    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    
    file_observable = root_analysis.get_observable(file_observable.uuid)
    assert file_observable
    email_analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    assert isinstance(email_analysis, EmailAnalysis)
    email_analysis.load_details()

    assert email_analysis.parsing_error is None
    assert email_analysis.email
    # this sample email is also a journaled email message so it gets this env_mail_from value
    assert email_analysis.env_mail_from == 'unixfreak0037@gmail.com'
    assert isinstance(email_analysis.env_rcpt_to, list)
    assert len(email_analysis.env_rcpt_to) == 1
    assert email_analysis.env_rcpt_to[0] == 'jwdavison@company.com'
    assert email_analysis.mail_from == 'John Davison <unixfreak0037@gmail.com>'
    assert isinstance(email_analysis.mail_to, list)
    assert len(email_analysis.mail_to) == 1
    assert email_analysis.mail_to[0] == 'jwdavison@company.com'
    assert email_analysis.reply_to is None
    assert email_analysis.subject == 'canary #3'
    assert email_analysis.decoded_subject == email_analysis.subject
    assert email_analysis.message_id == '<CANTOGZsMiMb+7aB868zXSen_fO=NS-qFTUMo9h2eHtOexY8Qhw@mail.gmail.com>'
    assert email_analysis.originating_ip is None
    assert isinstance(email_analysis.received, list)
    assert len(email_analysis.received) == 6
    assert isinstance(email_analysis.headers, list)
    assert isinstance(email_analysis.log_entry, dict)
    assert email_analysis.x_mailer is None
    assert email_analysis.body
    assert isinstance(email_analysis.attachments, list)
    assert len(email_analysis.attachments) == 0

    email_address_obervables = email_analysis.get_observables_by_type(F_EMAIL_ADDRESS)
    assert set([_.value for _ in email_address_obervables]) == set(['jwdavison@company.com', 'unixfreak0037@gmail.com'])

    email_conversation_obervables = email_analysis.get_observables_by_type(F_EMAIL_CONVERSATION)
    assert set([_.value for _ in email_conversation_obervables]) == set([create_email_conversation('unixfreak0037@gmail.com', 'jwdavison@company.com')])

    message_id_obervables = email_analysis.get_observables_by_type(F_MESSAGE_ID)
    assert set([_.value for _ in message_id_obervables]) == set(['<CANTOGZsMiMb+7aB868zXSen_fO=NS-qFTUMo9h2eHtOexY8Qhw@mail.gmail.com>'])

    email_delivery_obervables = email_analysis.get_observables_by_type(F_EMAIL_DELIVERY)
    assert set([_.value for _ in email_delivery_obervables]) == set([create_email_delivery('<CANTOGZsMiMb+7aB868zXSen_fO=NS-qFTUMo9h2eHtOexY8Qhw@mail.gmail.com>', 'jwdavison@company.com')])

    file_observables = email_analysis.get_observables_by_type(F_FILE)
    assert (set([_.file_name for _ in file_observables]) ==
                        set(['splunk_logging.email.rfc822.unknown_text_plain_000',
                            'splunk_logging.email.rfc822.unknown_text_html_000',
                            'splunk_logging.email.rfc822.headers',
                            'splunk_logging.email.rfc822.combined']))

    for file_observable in file_observables:
        if file_observable.value == 'splunk_logging.email.rfc822.unknown_text_plain_000':
            assert file_observable.has_directive(DIRECTIVE_EXTRACT_URLS)
            assert file_observable.has_directive(DIRECTIVE_PREVIEW)
        elif file_observable.value == 'splunk_logging.email.rfc822.unknown_text_html_000':
            assert file_observable.has_directive(DIRECTIVE_EXTRACT_URLS)

@pytest.mark.integration
def test_basic_smtp_email_parsing(root_analysis, datadir):

    # parse a basic email message we got from the smtp collector

    root_analysis.alert_type = ANALYSIS_TYPE_BRO_SMTP
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/smtp.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    observable = root_analysis.add_observable_by_spec(F_EMAIL_ADDRESS, 'unixfreak0037@gmail.com')
    observable.add_tag('smtp_mail_from')
    observable = root_analysis.add_observable_by_spec(F_EMAIL_ADDRESS, 'John.Davison@company.com')
    observable.add_tag('smtp_rcpt_to')
    observable = root_analysis.add_observable_by_spec(F_EMAIL_ADDRESS, 'Jane.Doe@company.com')
    observable.add_tag('smtp_rcpt_to')
    root_analysis.save()
    root_analysis.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    
    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    
    file_observable = root_analysis.get_observable(file_observable.uuid)
    assert file_observable
    email_analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    assert isinstance(email_analysis, EmailAnalysis)
    email_analysis.load_details()

    assert email_analysis.parsing_error is None
    assert email_analysis.email
    assert email_analysis.env_mail_from == 'unixfreak0037@gmail.com'
    assert isinstance(email_analysis.env_rcpt_to, list)
    assert len(email_analysis.env_rcpt_to) == 2
    for index in range(2):
        assert email_analysis.env_rcpt_to[index] in ['john.davison@company.com', 'jane.doe@company.com']

    assert email_analysis.mail_from == 'John Davison <unixfreak0037@gmail.com>'
    assert isinstance(email_analysis.mail_to, list)
    assert len(email_analysis.mail_to) == 1
    assert email_analysis.mail_to[0] == '"Davison, John" <John.Davison@company.com>'

    email_address_obervables = email_analysis.get_observables_by_type(F_EMAIL_ADDRESS)
    assert set([_.value for _ in email_address_obervables]) == set(['john.davison@company.com', 'unixfreak0037@gmail.com', 'jane.doe@company.com'])

    email_conversation_obervables = email_analysis.get_observables_by_type(F_EMAIL_CONVERSATION)
    assert (set([_.value for _ in email_conversation_obervables]) ==
                        set([create_email_conversation('unixfreak0037@gmail.com', 'john.davison@company.com'),
                            create_email_conversation('unixfreak0037@gmail.com', 'jane.doe@company.com')]))

    message_id_obervables = email_analysis.get_observables_by_type(F_MESSAGE_ID)
    assert (set([_.value for _ in message_id_obervables]) ==
                        set(['<CANTOGZshnHG073SKFD9aA-TxAu6UVnTwMbYFYMH7iCNhkenwvg@mail.gmail.com>']))

    email_delivery_obervables = email_analysis.get_observables_by_type(F_EMAIL_DELIVERY)
    assert (set([_.value for _ in email_delivery_obervables]) ==
                        set([create_email_delivery('<CANTOGZshnHG073SKFD9aA-TxAu6UVnTwMbYFYMH7iCNhkenwvg@mail.gmail.com>', 'john.davison@company.com'),
                            create_email_delivery('<CANTOGZshnHG073SKFD9aA-TxAu6UVnTwMbYFYMH7iCNhkenwvg@mail.gmail.com>', 'jane.doe@company.com')]))

    file_observables = email_analysis.get_observables_by_type(F_FILE)
    assert (set([_.file_name for _ in file_observables]) ==
                        set(['smtp.email.rfc822.unknown_text_plain_000',
                            'smtp.email.rfc822.unknown_text_html_000',
                            'smtp.email.rfc822.headers',
                            'smtp.email.rfc822.combined']))

    for file_observable in file_observables:
        if file_observable.value == 'smtp.email.rfc822.unknown_text_plain_000':
            assert file_observable.has_directive(DIRECTIVE_EXTRACT_URLS)
            assert file_observable.has_directive(DIRECTIVE_PREVIEW)
        elif file_observable.value == 'smtp.email.rfc822.unknown_text_html_000':
            assert file_observable.has_directive(DIRECTIVE_EXTRACT_URLS)

@pytest.mark.integration
def test_alert_renaming(root_analysis, datadir):

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/splunk_logging.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    file_observable.add_directive(DIRECTIVE_RENAME_ANALYSIS)
    root_analysis.save()
    root_analysis.schedule()
    old_description = root_analysis.description
    
    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    
    root_analysis = load_root(get_storage_dir(root_analysis.uuid))

    # the name of the alert should have changed
    assert root_analysis.description == f'{old_description} - canary #3'

@pytest.mark.integration
def test_o365_journal_email_parsing(root_analysis, datadir):

    # parse an office365 journaled message

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/o365_journaled.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    
    file_observable = root_analysis.get_observable(file_observable.uuid)
    assert file_observable
    email_analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    assert isinstance(email_analysis, EmailAnalysis)
    email_analysis.load_details()
    assert email_analysis.parsing_error is None
    assert email_analysis.email
    assert email_analysis.env_mail_from == 'ap@someothercompany.com'
    assert (isinstance(email_analysis.env_rcpt_to, list))
    assert len(email_analysis.env_rcpt_to) == 1
    assert email_analysis.env_rcpt_to[0] == 'lulu.zingzing@company.com'
    assert email_analysis.mail_from == 'Bobbie Fruitypie <ap@someothercompany.com>'
    assert isinstance(email_analysis.mail_to, list)
    assert len(email_analysis.mail_to) == 1
    # NOTE the To: is different than the env_rcpt_to in this case
    assert email_analysis.mail_to[0] == '<random.person@whatever.com>'
    assert email_analysis.reply_to is None
    assert email_analysis.subject == 'INVOICE PDL-06-38776'
    assert email_analysis.decoded_subject == email_analysis.subject
    assert email_analysis.message_id == '<13268020124593518925.93733CB7019D1C46@company.com>'
    assert email_analysis.originating_ip is None
    assert isinstance(email_analysis.received, list)
    assert len(email_analysis.received) == 7
    assert isinstance(email_analysis.headers, list)
    assert isinstance(email_analysis.log_entry, dict)
    assert email_analysis.x_mailer is None
    assert email_analysis.body
    assert isinstance(email_analysis.attachments, list)
    assert len(email_analysis.attachments) == 0

@pytest.mark.integration
def test_nested_rfc822_pdf_extraction(root_analysis, datadir):
    """Test that PDFs embedded in nested message/rfc822 parts are properly extracted.

    This tests a specific email structure where:
    - Outer email is multipart/mixed (O365 journal wrapper)
    - Contains a message/rfc822 part (the journaled email)
    - That inner email contains another message/rfc822 part
    - The innermost message/rfc822 has Content-Type: application/pdf directly
      (the PDF is the body of that inner email, not a separate MIME part)

    Without the fix, the PDF would not be extracted because the code would skip
    processing the inner message/rfc822 when it matched the target message-id.
    """
    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/nested_rfc822_pdf.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))

    file_observable = root_analysis.get_observable(file_observable.uuid)
    assert file_observable
    email_analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    assert isinstance(email_analysis, EmailAnalysis)
    email_analysis.load_details()
    assert email_analysis.parsing_error is None

    # Find the extracted PDF file
    pdf_observables = [
        obs for obs in root_analysis.all_observables
        if obs.type == F_FILE and obs.file_name and 'test_document.pdf' in obs.file_name
    ]
    assert len(pdf_observables) >= 1, "PDF should be extracted from nested message/rfc822"

    # Verify the PDF content is valid (starts with %PDF-)
    pdf_observable = pdf_observables[0]
    with open(pdf_observable.full_path, 'rb') as f:
        pdf_content = f.read()
    assert pdf_content.startswith(b'%PDF-'), "Extracted file should be a valid PDF"


@pytest.mark.parametrize("whitelist_item", [
    "smtp_from:ap@someothercompany.com",
    "smtp_to:lulu.zingzing@company.com",
])
@pytest.mark.integration
def test_whitelisting(root_analysis, whitelist_item, datadir):

    whitelist_path = os.path.join(get_temp_dir(), 'brotex.whitelist')
    get_analysis_module_config('email_analyzer').whitelist_path = whitelist_path

    if os.path.exists(whitelist_path):
        os.remove(whitelist_path)

    with open(whitelist_path, 'w') as fp:
        fp.write(whitelist_item)

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/o365_journaled.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    
    file_observable = root_analysis.get_observable(file_observable.uuid)
    file_observable
    email_analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    assert not email_analysis

@pytest.mark.integration
def test_automated_msoffice_decryption(root_analysis, datadir):
    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/encrypted_msoffice.email.rfc822'))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.configuration_manager.enable_module('msoffice_encryption_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    
    # XXX this changes because it gets turned into an alert
    alert = load_alert(root_analysis.uuid)

    from saq.modules.email import EmailAnalysis
    file_observable = alert.root_analysis.get_observable(file_observable.uuid)
    assert file_observable
    # make sure we extracted the encrypted office document
    email_analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    file_observable = email_analysis.find_observable(lambda o: o.type == F_FILE and o.file_name == 'info_3805.xls')
    assert file_observable
    # make sure we analyzed it
    from saq.modules.email import MSOfficeEncryptionAnalysis
    msoffice_analysis = file_observable.get_and_load_analysis(MSOfficeEncryptionAnalysis)
    assert isinstance(msoffice_analysis, MSOfficeEncryptionAnalysis)
    # make sure we got the right password
    assert msoffice_analysis.password == '709384'
    # and that we decrypted it
    assert msoffice_analysis.find_observable(lambda o: o.type == F_FILE and o.file_name == 'info_3805.xls.decrypted')

@pytest.mark.integration
def test_message_id_remediation(root_analysis, datadir):

    #
    # if the message_id has the remediate directive, then the corresponding email delivery should also have it

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/splunk_logging.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    message_id_observable = root_analysis.add_observable_by_spec(F_MESSAGE_ID, '<CANTOGZsMiMb+7aB868zXSen_fO=NS-qFTUMo9h2eHtOexY8Qhw@mail.gmail.com>')
    message_id_observable.add_directive(DIRECTIVE_REMEDIATE)
    root_analysis.save()
    root_analysis.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    
    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    
    file_observable = root_analysis.get_observable(file_observable.uuid)
    assert file_observable
    email_analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    assert email_analysis
    email_delivery = email_analysis.get_observables_by_type(F_EMAIL_DELIVERY)
    assert len(email_delivery) == 1
    email_delivery = email_delivery[0]
    assert email_delivery.message_id == message_id_observable.value
    assert email_delivery.has_directive(DIRECTIVE_REMEDIATE)

    #
    # if the message does NOT have the directive then the email delivery should also NOT have the directive
    #

    root_analysis = create_root_analysis()
    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    root_analysis.initialize_storage()
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/splunk_logging.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    message_id_observable = root_analysis.add_observable_by_spec(F_MESSAGE_ID, '<CANTOGZsMiMb+7aB868zXSen_fO=NS-qFTUMo9h2eHtOexY8Qhw@mail.gmail.com>')
    root_analysis.save()
    root_analysis.schedule()
    
    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    
    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    file_observable = root_analysis.get_observable(file_observable.uuid)
    assert file_observable
    email_analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    assert email_analysis
    email_delivery = email_analysis.get_observables_by_type(F_EMAIL_DELIVERY)
    assert len(email_delivery) == 1
    email_delivery = email_delivery[0]
    assert email_delivery.message_id == message_id_observable.value
    assert not email_delivery.has_directive(DIRECTIVE_REMEDIATE)

@pytest.mark.unit
def test_export_to_brocess(test_context):
    with get_db_connection(DB_BROCESS) as db:
        _cursor = db.cursor()
        _cursor.execute("DELETE FROM smtplog")
        db.commit()

    analyzer = EmailLoggingAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_EMAIL_LOGGER))

    analyzer.export_to_brocess({
        "mail_from": "john@netflix.com",
        "env_rcpt_to": ["somebody@host.com"],
    })

    with get_db_connection(DB_BROCESS) as db:
        _cursor = db.cursor()
        _cursor.execute("SELECT source, destination, numconnections FROM smtplog WHERE source = %s AND destination = %s AND numconnections = 1", ("john@netflix.com", "somebody@host.com"))
        result = _cursor.fetchone()
        assert result

@pytest.mark.unit
def test_export_to_brocess_large_email(test_context):
    with get_db_connection(DB_BROCESS) as db:
        _cursor = db.cursor()
        _cursor.execute("DELETE FROM smtplog")
        db.commit()

    analyzer = EmailLoggingAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_EMAIL_LOGGER))
    mail_from = "john" + ("0" * 255) + "@netflix.com"
    mail_to = "somebody" + ("0" * 255) + "@host.com"
    analyzer.export_to_brocess({
        "mail_from": mail_from, 
        "env_rcpt_to": [mail_to],
    })

    with get_db_connection(DB_BROCESS) as db:
        _cursor = db.cursor()
        _cursor.execute("SELECT source, destination, numconnections FROM smtplog WHERE source = %s AND destination = %s AND numconnections = 1", (mail_from[:255], mail_to[:255]))
        result = _cursor.fetchone()
        assert result