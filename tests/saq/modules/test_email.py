from datetime import datetime
import email
import filecmp
import gzip
import json
import os
import shutil
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pytest
import pytz

from saq.analysis.root import RootAnalysis, load_root
from saq.configuration.config import get_config, get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_EMAIL_LOGGER, ANALYSIS_TYPE_BRO_SMTP, ANALYSIS_TYPE_MAILBOX, DB_BROCESS, DB_EMAIL_ARCHIVE, FILE_SUBDIR, DIRECTIVE_ARCHIVE, DIRECTIVE_EXTRACT_URLS, DIRECTIVE_ORIGINAL_EMAIL, DIRECTIVE_PREVIEW, DIRECTIVE_REMEDIATE, DIRECTIVE_RENAME_ANALYSIS, DIRECTIVE_RENDER, EVENT_TIME_FORMAT_JSON_TZ, F_EMAIL_ADDRESS, F_EMAIL_CC, F_EMAIL_CONVERSATION, F_EMAIL_DELIVERY, F_EMAIL_DKIM_SIGNING_DOMAIN, F_EMAIL_FIRST_HOP_FROM, F_EMAIL_FIRST_HOP_HELO, F_EMAIL_FIRST_HOP_IP, F_EMAIL_FROM, F_EMAIL_SENDER_TENANT_ID, F_EMAIL_TO, F_FILE, F_IP, F_MESSAGE_ID, F_URL, create_email_conversation, create_email_delivery
from saq.observables.type_hierarchy import get_type_hierarchy
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
from saq.modules.email.constants import KEY_LOG_ENTRY
from saq.modules.email.rfc822 import (
    EmailAnalysis,
    EmailAnalyzerConfig,
    EmailProviderHeaders,
    TAG_ANONYMOUS_DIRECT_SEND,
    TAG_AUTHENTICATION_FAILED,
    TAG_SPOOFED_INTERNAL,
    get_dkim_signing_domains,
    get_sender_tenant_id,
    normalize_ip_header_value,
    parse_email_authentication,
    resolve_first_hop,
)
from saq.modules.email.constants import (
    KEY_COMPAUTH_REASON,
    KEY_COMPAUTH_RESULT,
    KEY_DMARC_RESULT,
    KEY_IS_ANONYMOUS_DIRECT_SEND,
    KEY_SPF_RESULT,
)
from saq.observables.email import EmailFirstHopIPObservable
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
def test_combined_buffer_with_unaddable_file_observable(root_analysis, datadir, monkeypatch):
    # regression: when add_file_observable returns None (per-type observable limit reached) for an
    # auto-generated part, the combined buffer must still build without duplicating the files/ path prefix
    from saq.analysis.analysis import Analysis

    original_add_file_observable = Analysis.add_file_observable

    def limited_add_file_observable(self, path, *args, **kwargs):
        # simulate the per-type observable limit being hit for the auto-generated (unknown_) parts
        if "unknown_" in str(path):
            return None
        return original_add_file_observable(self, path, *args, **kwargs)

    monkeypatch.setattr(Analysis, "add_file_observable", limited_add_file_observable)

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / "emails/splunk_logging.email.rfc822"))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("file_type", "test_groups")
    engine.configuration_manager.enable_module("email_analyzer", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    file_observable = root_analysis.get_observable(file_observable.uuid)
    analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    assert analysis

    # tracked attachment paths must always be relative to the files dir, never absolute or doubled
    for attachment_name in analysis.email[KEY_LOG_ENTRY]["attachment_names"]:
        assert not os.path.isabs(attachment_name)
        assert "{0}{1}{0}".format(os.sep, FILE_SUBDIR) not in attachment_name

    # the combined buffer should have been created and should contain the decoded html part;
    # before the fix the doubled path caused the html part to be silently skipped
    combined_files = [o for o in root_analysis.all_observables
                      if o.type == F_FILE and o.file_name.endswith(".combined")]
    assert combined_files, "combined email file was not created"
    with open(combined_files[0].full_path, "rb") as fp:
        combined_content = fp.read()
    assert b"197.210.28.107" in combined_content


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
            }, content_type='multipart/form-data', headers = { 'x-ace-auth': get_config().api.api_key })

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
    assert len(smtp_fields) == 26
    
    with open(fields_file, 'r') as fp:
        fields = fp.readline().strip()

    assert fields == ('date,attachment_count,attachment_hashes,attachment_names,attachment_sizes,attachment_types,bcc,'
                                'cc,env_mail_from,env_rcpt_to,extracted_urls,first_received,headers,last_received,mail_from,'
                                'mail_to,message_id,originating_ip,path,reply_to,size,subject,subject_raw,user_agent,archive_path,x_mailer')

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

    hierarchy = get_type_hierarchy()
    email_address_obervables = [o for o in email_analysis.observables if hierarchy.is_subtype(o.type, F_EMAIL_ADDRESS)]
    assert set([_.value for _ in email_address_obervables]) == set(['jwdavison@company.com', 'unixfreak0037@gmail.com'])

    email_conversation_obervables = email_analysis.get_observables_by_type(F_EMAIL_CONVERSATION)
    assert set([_.value for _ in email_conversation_obervables]) == set([create_email_conversation('unixfreak0037@gmail.com', 'jwdavison@company.com')])

    message_id_obervables = email_analysis.get_observables_by_type(F_MESSAGE_ID)
    assert set([_.value for _ in message_id_obervables]) == set(['<CANTOGZsMiMb+7aB868zXSen_fO=NS-qFTUMo9h2eHtOexY8Qhw@mail.gmail.com>'])

    email_delivery_obervables = email_analysis.get_observables_by_type(F_EMAIL_DELIVERY)
    assert set([_.value for _ in email_delivery_obervables]) == set([create_email_delivery('<CANTOGZsMiMb+7aB868zXSen_fO=NS-qFTUMo9h2eHtOexY8Qhw@mail.gmail.com>', 'jwdavison@company.com')])

    file_observables = email_analysis.get_observables_by_type(F_FILE)
    assert (set([_.file_name for _ in file_observables]) ==
                        set(['splunk_logging.email.rfc822.unknown_text_plain_000.txt',
                            'splunk_logging.email.rfc822.unknown_text_html_000.html',
                            'splunk_logging.email.rfc822.headers',
                            'splunk_logging.email.rfc822.combined']))

    for file_observable in file_observables:
        if file_observable.value == 'splunk_logging.email.rfc822.unknown_text_plain_000.txt':
            assert file_observable.has_directive(DIRECTIVE_EXTRACT_URLS)
            assert file_observable.has_directive(DIRECTIVE_PREVIEW)
        elif file_observable.value == 'splunk_logging.email.rfc822.unknown_text_html_000.html':
            assert file_observable.has_directive(DIRECTIVE_EXTRACT_URLS)

@pytest.mark.integration
def test_html_fragment_body_gets_html_extension(root_analysis):
    """Regression: an HTML email body that is a bare fragment (starts with <div>,
    no <!DOCTYPE>/<html> wrapper) is misdetected by libmagic as text/plain. The
    extracted body must still be named with a content-type-derived extension
    (.html) so phishkit's html/pdf extension allow-list renders it instead of
    silently skipping it. See the analyzed alert 6fac833d-... for the original miss."""

    # synthesize a minimal email whose text/html part is a bare HTML fragment
    msg = MIMEMultipart('alternative')
    msg['From'] = 'attacker@example.com'
    msg['To'] = 'victim@company.com'
    msg['Subject'] = 'fragment body'
    msg['Message-ID'] = '<fragment-body-test@example.com>'
    msg.attach(MIMEText('plain text body', 'plain'))
    # no doctype / <html> / <head> — exactly what defeats libmagic's HTML sniffing
    msg.attach(MIMEText('<div id="isPasted"><span>Hello</span></div>', 'html'))

    email_path = os.path.join(get_temp_dir(), 'fragment.email.rfc822')
    with open(email_path, 'wb') as fp:
        fp.write(msg.as_bytes())

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(email_path)
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

    file_observables = email_analysis.get_observables_by_type(F_FILE)

    # the HTML body must carry a real .html extension and the render directive
    html_body = next((o for o in file_observables if 'unknown_text_html_000' in o.file_name), None)
    assert html_body is not None
    assert html_body.file_name.endswith('.html')
    assert html_body.has_directive(DIRECTIVE_RENDER)

    # the plain text body gets a .txt extension and the preview directive
    plain_body = next((o for o in file_observables if 'unknown_text_plain_000' in o.file_name), None)
    assert plain_body is not None
    assert plain_body.file_name.endswith('.txt')
    assert plain_body.has_directive(DIRECTIVE_PREVIEW)


def _build_attachment_email(declared_content_type: str | None, message_id: str):
    """Synthesizes an email with one HTML attachment whose Content-Type header is
    set verbatim to declared_content_type (None omits the header entirely).

    MIMEText/MIMEBase won't emit a malformed type, so the header is written by
    hand -- that is the whole point of these tests.
    """
    headers = [
        'From: attacker@example.com',
        'To: victim@company.com',
        f'Subject: attachment {message_id}',
        f'Message-ID: <{message_id}@example.com>',
        'MIME-Version: 1.0',
        'Content-Type: multipart/mixed; boundary="BOUND"',
        '',
        '--BOUND',
        'Content-Type: text/plain; charset="us-ascii"',
        '',
        'see attached',
        '',
        '--BOUND',
    ]
    if declared_content_type is not None:
        headers.append(f'Content-Type: {declared_content_type}')
    headers += [
        'Content-Disposition: attachment; filename="invoice.html"',
        '',
        '<!DOCTYPE html><html><body><a href="https://example.com/x">x</a></body></html>',
        '',
        '--BOUND--',
        '',
    ]
    return '\r\n'.join(headers).encode()


def _analyze_attachment_email(root_analysis, raw_email: bytes, name: str):
    """Runs EmailAnalyzer over a synthesized email and returns the attachment observable."""
    email_path = os.path.join(get_temp_dir(), f'{name}.email.rfc822')
    with open(email_path, 'wb') as fp:
        fp.write(raw_email)

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(email_path)
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    reloaded = load_root(get_storage_dir(root_analysis.uuid))
    file_observable = reloaded.get_observable(file_observable.uuid)
    email_analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    assert isinstance(email_analysis, EmailAnalysis)
    return next(
        (o for o in email_analysis.get_observables_by_type(F_FILE)
         if o.file_name.endswith('invoice.html')),
        None,
    )


@pytest.mark.integration
def test_malformed_content_type_attachment_still_gets_render(root_analysis):
    """An attachment declaring a malformed Content-Type must still be rendered.

    "Content-Type: text" has no subtype, so it is not a valid MIME type, and
    python normalizes any unparseable Content-Type to the RFC 2045 default
    text/plain -- the one value that takes the preview branch. That let a real
    sample suppress rendering of an HTML attachment for free: the sender writes
    the header, and the failure direction is toward not analyzing.
    """
    attachment = _analyze_attachment_email(
        root_analysis, _build_attachment_email('text; name="invoice"', 'malformed-ct'), 'malformed')

    assert attachment is not None
    assert attachment.has_directive(DIRECTIVE_RENDER)
    assert not attachment.has_directive(DIRECTIVE_PREVIEW)


@pytest.mark.integration
def test_honest_plain_text_attachment_still_gets_preview(root_analysis):
    """A genuinely-declared text/plain attachment keeps preview -- the malformed
    check must not turn every attachment into a render."""
    attachment = _analyze_attachment_email(
        root_analysis, _build_attachment_email('text/plain; charset="us-ascii"', 'honest-plain'), 'honest')

    assert attachment is not None
    assert attachment.has_directive(DIRECTIVE_PREVIEW)
    assert not attachment.has_directive(DIRECTIVE_RENDER)


@pytest.mark.integration
def test_absent_content_type_attachment_gets_preview(root_analysis):
    """No Content-Type header at all is NOT an evasion: RFC 2045 says a part
    without one genuinely is text/plain. Preview stays correct."""
    attachment = _analyze_attachment_email(
        root_analysis, _build_attachment_email(None, 'absent-ct'), 'absent')

    assert attachment is not None
    assert attachment.has_directive(DIRECTIVE_PREVIEW)
    assert not attachment.has_directive(DIRECTIVE_RENDER)

@pytest.mark.integration
def test_long_filename_does_not_crash_analyzer(root_analysis, datadir):
    """Regression: a .eml basename at the 255-byte per-component limit used to crash
    analyze_rfc822 with ENAMETOOLONG when it tried to write '<basename>.headers'
    (263 bytes). The analyzer must now shorten the derived basenames."""

    long_basename = "a" * 251 + ".eml"
    assert len(long_basename.encode("utf-8")) == 255

    src = str(datadir / 'emails/splunk_logging.email.rfc822')
    dst = str(datadir / 'emails' / long_basename)
    shutil.copy(src, dst)

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(dst)
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
    assert email_analysis.parsing_error is None

    file_observables = email_analysis.get_observables_by_type(F_FILE)
    file_names = [_.file_name for _ in file_observables]

    # Every derived file must fit within the per-component limit.
    for name in file_names:
        assert len(name.encode("utf-8")) <= 255, f"{name!r} exceeds NAME_MAX"

    # Headers and combined files should still be produced (under shortened names).
    assert any(name.endswith(".headers") for name in file_names), file_names
    assert any(name.endswith(".combined") for name in file_names), file_names

@pytest.mark.integration
def test_nested_relative_path_does_not_crash_analyzer(root_analysis, datadir):
    """Regression: when an email lives at a nested relative path (e.g. an officeparser
    stream extracted under '<parent>.msg.officeparser/'), `_file.file_path` contains
    '/' and previously hit `assert os.sep not in basename` inside
    `shorten_basename_for_suffix`, crashing the entire email analysis."""

    nested_target = "parent.msg.officeparser/stream_81.eml"
    src = str(datadir / 'emails/splunk_logging.email.rfc822')

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(src, target_path=nested_target)
    assert file_observable is not None
    assert file_observable.file_path == nested_target  # path includes the subdirectory
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
    assert email_analysis.parsing_error is None

    file_observables = email_analysis.get_observables_by_type(F_FILE)
    derived_paths = [o.file_path for o in file_observables]

    # Layout must be preserved — derived files land under the same parent subdir,
    # not flattened to the root file directory.
    headers_paths = [p for p in derived_paths if p.endswith(".headers")]
    combined_paths = [p for p in derived_paths if p.endswith(".combined")]
    assert headers_paths, derived_paths
    assert combined_paths, derived_paths
    for p in headers_paths + combined_paths:
        assert p.startswith("parent.msg.officeparser/"), p

@pytest.mark.integration
def test_multi_recipient_to_cc_observables(root_analysis, datadir):
    """A single To: header with multiple addresses, plus a CC: with mixed local/external recipients,
    should produce one F_EMAIL_TO per To: address and one F_EMAIL_CC per CC: address.

    NOTE on F_EMAIL_DELIVERY: a delivery observable is created for EVERY local recipient the
    message reached — envelope, To: and CC: — so the remediation timeline reflects the full
    delivery footprint. Non-local recipients (e.g. outsider@external.example) are skipped."""

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/multi_recipient_to_cc.email.rfc822'))
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

    message_id = '<multi-recipient-test-12345@external.example>'
    assert email_analysis.message_id == message_id

    # both To: recipients must appear as F_EMAIL_TO observables (not just the first)
    email_to_values = {o.value for o in email_analysis.observables if o.type == F_EMAIL_TO}
    assert email_to_values == {'alice@company.com', 'bob@company.com'}

    # all three CC: recipients must appear as F_EMAIL_CC observables
    email_cc_values = {o.value for o in email_analysis.observables if o.type == F_EMAIL_CC}
    assert email_cc_values == {'carol@company.com', 'outsider@external.example', 'dan@company.com'}

    # F_EMAIL_DELIVERY observables: one per local recipient across the To: and CC: headers.
    # outsider@external.example is a non-local recipient and must NOT get a delivery observable.
    delivery_values = {o.value for o in email_analysis.get_observables_by_type(F_EMAIL_DELIVERY)}
    assert delivery_values == {
        create_email_delivery(message_id, 'alice@company.com'),
        create_email_delivery(message_id, 'bob@company.com'),
        create_email_delivery(message_id, 'carol@company.com'),
        create_email_delivery(message_id, 'dan@company.com'),
    }

    # mail_to should reflect both header To: addresses (multi-recipient parsing)
    assert email_analysis.mail_to_addresses == ['alice@company.com', 'bob@company.com']

    # log_entry path should contain the received-from IP (Fix D regression check)
    assert email_analysis.log_entry is not None
    assert email_analysis.log_entry['path'] is not None
    assert any('192.0.2.10' in entry for entry in email_analysis.log_entry['path'])

    # cc/bcc in log_entry now use get_address_list (Fix K regression check)
    assert isinstance(email_analysis.log_entry['cc'], list)
    assert 'carol@company.com' in email_analysis.log_entry['cc']
    assert 'outsider@external.example' in email_analysis.log_entry['cc']

    # Return-Path header is present, so KEY_RETURN_PATH should be the parsed address (Fix G)
    assert email_analysis.return_path == 'sender@external.example'

@pytest.mark.integration
def test_multi_recipient_delivery_directive_propagation(root_analysis, datadir):
    """When the message-id observable carries DIRECTIVE_REMEDIATE, the directive must be
    copied to the delivery observable of EVERY local recipient, not just the primary one."""

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/multi_recipient_to_cc.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    message_id_observable = root_analysis.add_observable_by_spec(F_MESSAGE_ID, '<multi-recipient-test-12345@external.example>')
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
    assert isinstance(email_analysis, EmailAnalysis)

    message_id = '<multi-recipient-test-12345@external.example>'
    delivery_observables = email_analysis.get_observables_by_type(F_EMAIL_DELIVERY)
    delivery_values = {o.value for o in delivery_observables}
    assert delivery_values == {
        create_email_delivery(message_id, 'alice@company.com'),
        create_email_delivery(message_id, 'bob@company.com'),
        create_email_delivery(message_id, 'carol@company.com'),
        create_email_delivery(message_id, 'dan@company.com'),
    }

    # every local recipient's delivery observable must carry the remediate directive
    for delivery in delivery_observables:
        assert delivery.has_directive(DIRECTIVE_REMEDIATE), delivery.value

@pytest.mark.integration
def test_attachment_filename_multi_rfc2047_chunks(root_analysis, datadir):
    """An attachment whose filename uses multiple RFC 2047 encoded-word chunks should have
    all chunks decoded — not just the first. Old code dropped everything after [0]."""

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/multi_rfc2047_filename.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    file_observable = root_analysis.get_observable(file_observable.uuid)
    email_analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    email_analysis.load_details()
    assert email_analysis.parsing_error is None

    # the resulting attachment file observable's name should contain BOTH "Hello" and
    # "World" — i.e. all encoded-word chunks were decoded. With the old code, only
    # the first chunk ("Hello") was decoded and the rest of the filename was dropped.
    file_observables = email_analysis.get_observables_by_type(F_FILE)
    attachment_names = [o.file_name for o in file_observables]
    assert any('Hello' in n and 'World' in n for n in attachment_names), \
        f"expected an attachment whose decoded name contains both 'Hello' and 'World', got: {attachment_names!r}"

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

    hierarchy = get_type_hierarchy()
    email_address_obervables = [o for o in email_analysis.observables if hierarchy.is_subtype(o.type, F_EMAIL_ADDRESS)]
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
                        set(['smtp.email.rfc822.unknown_text_plain_000.txt',
                            'smtp.email.rfc822.unknown_text_html_000.html',
                            'smtp.email.rfc822.headers',
                            'smtp.email.rfc822.combined']))

    for file_observable in file_observables:
        if file_observable.value == 'smtp.email.rfc822.unknown_text_plain_000.txt':
            assert file_observable.has_directive(DIRECTIVE_EXTRACT_URLS)
            assert file_observable.has_directive(DIRECTIVE_PREVIEW)
        elif file_observable.value == 'smtp.email.rfc822.unknown_text_html_000.html':
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
def test_o365_journal_email_parsing_multiple_recipients(root_analysis, datadir):

    # parse an office365 journaled message with multiple recipients in the meta block

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/o365_journaled_multi_rcpt.email.rfc822'))
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
    assert isinstance(email_analysis.env_rcpt_to, list)
    assert len(email_analysis.env_rcpt_to) == 3
    assert 'lulu.zingzing@company.com' in email_analysis.env_rcpt_to
    assert 'bob.smith@company.com' in email_analysis.env_rcpt_to
    assert 'charlie.jones@company.com' in email_analysis.env_rcpt_to

    # verify an email_delivery observable was created for each recipient
    email_delivery_observables = email_analysis.get_observables_by_type(F_EMAIL_DELIVERY)
    assert len(email_delivery_observables) == 3
    delivery_values = [o.value for o in email_delivery_observables]
    message_id = email_analysis.message_id
    assert create_email_delivery(message_id, 'lulu.zingzing@company.com') in delivery_values
    assert create_email_delivery(message_id, 'bob.smith@company.com') in delivery_values
    assert create_email_delivery(message_id, 'charlie.jones@company.com') in delivery_values

@pytest.mark.integration
def test_o365_journal_email_parsing_expanded_recipients(root_analysis, datadir):

    # parse an office365 journaled message with ", Expanded:" suffix on recipient lines

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/o365_journaled_expanded_rcpt.email.rfc822'))
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
    assert isinstance(email_analysis.env_rcpt_to, list)
    assert len(email_analysis.env_rcpt_to) == 3
    assert 'lulu.zingzing@company.com' in email_analysis.env_rcpt_to
    assert 'bob.smith@company.com' in email_analysis.env_rcpt_to
    assert 'charlie.jones@company.com' in email_analysis.env_rcpt_to

    # verify an email_delivery observable was created for each recipient
    email_delivery_observables = email_analysis.get_observables_by_type(F_EMAIL_DELIVERY)
    assert len(email_delivery_observables) == 3
    delivery_values = [o.value for o in email_delivery_observables]
    message_id = email_analysis.message_id
    assert create_email_delivery(message_id, 'lulu.zingzing@company.com') in delivery_values
    assert create_email_delivery(message_id, 'bob.smith@company.com') in delivery_values
    assert create_email_delivery(message_id, 'charlie.jones@company.com') in delivery_values

@pytest.mark.integration
def test_o365_journal_email_parsing_quoted_printable_meta(root_analysis, datadir):
    """Test that O365 journal meta block is parsed correctly when using quoted-printable encoding.

    The meta block may use Content-Transfer-Encoding: quoted-printable with a UTF-8 BOM,
    soft line breaks, and encoded characters. The parser must decode these before applying
    the regex.
    """

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/o365_journaled_qp_meta.email.rfc822'))
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
    assert email_analysis.env_mail_from == 'jane.smith@widgetsinc.com'
    assert isinstance(email_analysis.env_rcpt_to, list)
    assert len(email_analysis.env_rcpt_to) == 1
    assert email_analysis.env_rcpt_to[0] == 'john.doe@acmecorp.com'
    assert email_analysis.message_id == '<AAAAAA1111BBBBBB2222@AAAAAA1111.namprd10.prod.outlook.com>'

@pytest.mark.integration
def test_o365_journal_email_parsing_7bit_bom_meta(root_analysis, datadir):
    """Test that O365 journal meta block is parsed correctly when using 7bit CTE with a UTF-8 BOM.

    When the meta block uses Content-Transfer-Encoding: 7bit and contains a UTF-8 BOM,
    get_payload(decode=True) mangles the BOM via raw-unicode-escape encoding, causing the
    meta regex to fail. The fix uses get_payload() (without decode) for 7bit/8bit parts.
    """

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/o365_journaled_7bit_bom_meta.email.rfc822'))
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
    assert email_analysis.env_mail_from == 'john.smith@contractor.example'
    assert isinstance(email_analysis.env_rcpt_to, list)
    assert len(email_analysis.env_rcpt_to) == 3
    assert 'alice@acmecorp.com' in email_analysis.env_rcpt_to
    assert 'bob@acmecorp.com' in email_analysis.env_rcpt_to
    assert 'carol@acmecorp.com' in email_analysis.env_rcpt_to
    assert email_analysis.message_id == '<000001dcb67c$11223344$55667788$@contractor.example>'

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


@pytest.mark.integration
def test_nested_rfc822_bom_extraction(root_analysis, datadir):
    """A nested message/rfc822 attachment whose inner body contains a raw UTF-8 BOM must
    still be extracted as a child file observable.

    Previously the analyzer read the email as text and parsed it with
    `Parser().parsestr(...)`, so non-ASCII payload bytes (like a BOM) became `str` and
    `Message.as_bytes()` crashed with UnicodeEncodeError when re-serializing an ancestor
    message/rfc822 part. The wrapper's try/except swallowed the error, leaving no child
    observable and no analyst-visible trace. Switching to `BytesParser().parse(fp)`
    preserves the raw bytes so re-serialization succeeds.
    """
    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/nested_rfc822_bom.email.rfc822'))
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
    assert email_analysis.extraction_errors == [], (
        f"expected no extraction errors, got {email_analysis.extraction_errors}"
    )
    assert 'email_parse_incomplete' not in (file_observable.tags or [])

    # the inner nested email must be extracted as a child file observable
    # (ACE names extracted nested message/rfc822 parts as "<original>.email.rfc822")
    nested_email_observables = [
        obs for obs in root_analysis.all_observables
        if obs.type == F_FILE and obs.file_name and obs.file_name.endswith('.email.rfc822')
        and obs.uuid != file_observable.uuid
    ]
    assert len(nested_email_observables) >= 1, (
        "nested rfc822 email should be extracted as a child file observable"
    )

    # the extracted nested email should contain the payload.eml inner headers
    with open(nested_email_observables[0].full_path, 'rb') as fp:
        extracted = fp.read()
    assert b'<payload-inner@example.com>' in extracted, (
        "extracted nested email should contain the inner Message-ID"
    )


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
        _cursor.execute("SELECT source, destination, numconnections FROM smtplog WHERE source = %s AND destination = %s AND numconnections = 1", (mail_from[:255].encode("utf-8"), mail_to[:255].encode("utf-8")))
        result = _cursor.fetchone()
        assert result

@pytest.mark.unit
def test_export_to_brocess_multibyte_oversize(test_context):
    # smtplog.source/destination are varbinary(255) — a byte limit.
    # values whose UTF-8 encoding exceeds 255 bytes must not crash the export
    with get_db_connection(DB_BROCESS) as db:
        _cursor = db.cursor()
        _cursor.execute("DELETE FROM smtplog")
        db.commit()

    analyzer = EmailLoggingAnalyzer(
        context=test_context,
        config=get_analysis_module_config(ANALYSIS_MODULE_EMAIL_LOGGER))
    # "®" is 2 bytes in UTF-8: 200 ASCII + 60 multibyte = 260 chars / 320 bytes
    mail_from = ("a" * 200) + ("®" * 60) + "@x.com"
    mail_to = ("b" * 200) + ("®" * 60) + "@y.com"
    analyzer.export_to_brocess({
        "mail_from": mail_from,
        "env_rcpt_to": [mail_to],
    })

    with get_db_connection(DB_BROCESS) as db:
        _cursor = db.cursor()
        _cursor.execute("SELECT source, destination, LENGTH(source), LENGTH(destination) FROM smtplog")
        result = _cursor.fetchone()
        assert result
        source, destination, source_len, destination_len = result
        assert source_len <= 255
        assert destination_len <= 255
        assert source == mail_from.encode("utf-8")[:255]
        assert destination == mail_to.encode("utf-8")[:255]

@pytest.mark.integration
@pytest.mark.parametrize("email_file,expected_subject,expected_subject_raw", [
    ("emails/splunk_logging.email.rfc822", "canary #3", "canary #3"),
    ("emails/encoded_subject.email.rfc822", "Test Encoded Subject", "=?UTF-8?B?VGVzdCBFbmNvZGVkIFN1YmplY3Q=?="),
])
def test_log_entry_subject(root_analysis, datadir, email_file, expected_subject, expected_subject_raw):
    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / email_file))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("file_type", "test_groups")
    engine.configuration_manager.enable_module("email_analyzer", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    file_observable = root_analysis.get_observable(file_observable.uuid)
    assert file_observable
    email_analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    assert isinstance(email_analysis, EmailAnalysis)
    email_analysis.load_details()

    log_entry = email_analysis.log_entry
    assert log_entry is not None
    assert log_entry["subject"] == expected_subject
    assert log_entry["subject_raw"] == expected_subject_raw

    # KEY_SUBJECT must be a plain str (the raw, possibly RFC 2822-encoded form),
    # not an email.header.Header instance. KEY_DECODED_SUBJECT must be the decoded form.
    assert isinstance(email_analysis.subject, str)
    assert email_analysis.subject == expected_subject_raw
    assert email_analysis.decoded_subject == expected_subject

    # all values stored in KEY_HEADERS must be strings, not Header instances —
    # otherwise downstream JSON serialization and the .headers file write break.
    for name, value in email_analysis.headers:
        assert isinstance(name, str)
        assert isinstance(value, str)


#
# first hop / DKIM / sender tenant id header extraction
#

def _load_email(path):
    with open(path, 'rb') as fp:
        return email.message_from_binary_file(fp)


@pytest.mark.unit
def test_resolve_first_hop_authoritative_header(datadir):
    """The X-MS-* client IP header wins, and the matching Received: hop supplies the host."""

    # the journal envelope wraps the real message, so the authoritative headers are on the inner one
    outer = _load_email(str(datadir / 'emails/o365_journaled.email.rfc822'))
    inner = [
        sub
        for part in outer.walk() if part.get_content_type() == 'message/rfc822'
        for sub in part.get_payload()
    ][0]

    hop_ip, hop_helo, hop_from = resolve_first_hop(inner)
    assert hop_ip == '207.211.31.81'
    # the token after `from` (us-smtp-1.mimecast.com) is the HELO; the parens hold only the IP,
    # so there is no reverse-DNS host name
    assert hop_helo == 'us-smtp-1.mimecast.com'
    assert hop_from is None

    # the journal envelope itself only has internal relay hops, so it resolves to nothing
    assert resolve_first_hop(outer) == (None, None, None)


@pytest.mark.unit
def test_resolve_first_hop_local_domain_fallback(datadir):
    """Without an X-MS-* header we fall back to the hop accepted by one of our own hosts."""

    target_email = _load_email(str(datadir / 'emails/smtp.email.rfc822'))

    hop_ip, hop_helo, hop_from = resolve_first_hop(target_email)
    # Received: from mail-lf1-f52.google.com ([209.85.167.52]) by mailserver.company.com
    # the token after `from` is the HELO; the parens hold only the IP so there is no rDNS host
    assert hop_ip == '209.85.167.52'
    assert hop_helo == 'mail-lf1-f52.google.com'
    assert hop_from is None


@pytest.mark.unit
def test_resolve_first_hop_helo():
    """A helo=/HELO token on the perimeter hop becomes email_first_hop_helo."""

    for received in [
        'from relay.example.com (helo=Spoofed.Example.NET) by mailserver.company.com with ESMTP',
        'from relay.example.com (HELO Spoofed.Example.NET) by mailserver.company.com with ESMTP',
    ]:
        target_email = email.message_from_string(f'Received: {received}\r\n\r\nbody\r\n')
        hop_ip, hop_helo, hop_from = resolve_first_hop(target_email)
        assert hop_helo == 'spoofed.example.net'
        assert hop_from == 'relay.example.com'
        assert hop_ip is None


@pytest.mark.unit
def test_resolve_first_hop_helo_and_rdns_host():
    """`from HELO (rdns [ip])` splits the HELO (token) from the reverse-DNS host (in parens)."""

    target_email = email.message_from_string(
        'X-Sender-IP: 203.0.113.5\r\n'
        'Received: from HELO-NAME.example (rdns.sender.example [203.0.113.5]) by mx.company.com\r\n'
        '\r\nbody\r\n')

    hop_ip, hop_helo, hop_from = resolve_first_hop(target_email)
    assert hop_ip == '203.0.113.5'
    assert hop_helo == 'helo-name.example'
    assert hop_from == 'rdns.sender.example'


@pytest.mark.unit
def test_resolve_first_hop_ipv6():
    """IPv6 hop addresses must survive -- the older x-sender-ip handling strips them to junk."""

    target_email = email.message_from_string(
        'X-MS-Exchange-Organization-OriginalClientIPAddress: 2a01:111:f403:c201::3\r\n'
        'Received: from mail.example.com (2a01:111:f403:c201::3) by mailserver.company.com\r\n'
        '\r\nbody\r\n')

    hop_ip, hop_helo, hop_from = resolve_first_hop(target_email)
    assert hop_ip == '2a01:111:f403:c201::3'
    # token after `from` is the HELO; parens hold only the IP
    assert hop_helo == 'mail.example.com'
    assert hop_from is None


@pytest.mark.unit
def test_resolve_first_hop_missing():
    """Nothing to resolve means no observables, not a guess."""

    target_email = email.message_from_string('Subject: hello\r\n\r\nbody\r\n')
    assert resolve_first_hop(target_email) == (None, None, None)


@pytest.mark.unit
def test_normalize_ip_header_value():
    """Bracket decoration comes off, and IPv6 survives (it used to be stripped to junk)."""

    assert normalize_ip_header_value('[10.0.0.1]') == '10.0.0.1'
    assert normalize_ip_header_value(' 10.0.0.1 ') == '10.0.0.1'
    assert normalize_ip_header_value('[2a01:111:f403:c201::3]') == '2a01:111:f403:c201::3'
    assert normalize_ip_header_value('2a01:111:f403:c201::3') == '2a01:111:f403:c201::3'

    # garbage yields nothing rather than a mangled value
    assert normalize_ip_header_value('unknown') is None
    assert normalize_ip_header_value('') is None
    assert normalize_ip_header_value(None) is None


@pytest.mark.integration
def test_ipv6_originating_and_sender_ip(root_analysis, tmp_path):
    """X-Originating-IP / X-Sender-IP must survive as IPv6 addresses."""

    path = tmp_path / 'ipv6.email.rfc822'
    path.write_text(
        'Message-ID: <ipv6test@example.com>\r\n'
        'From: sender@example.com\r\n'
        'To: recipient@company.com\r\n'
        'Subject: ipv6\r\n'
        'X-Originating-IP: [2a01:111:f403:c201::3]\r\n'
        'X-Sender-IP: [2a01:111:f403:c201::4]\r\n'
        '\r\nbody\r\n')

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(path))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    file_observable = root_analysis.get_observable(file_observable.uuid)
    email_analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    assert isinstance(email_analysis, EmailAnalysis)
    email_analysis.load_details()

    assert email_analysis.originating_ip == '2a01:111:f403:c201::3'
    assert email_analysis.x_sender_ip == '2a01:111:f403:c201::4'

    ip_values = sorted(_.value for _ in email_analysis.get_observables_by_type(F_IP))
    assert ip_values == ['2a01:111:f403:c201::3', '2a01:111:f403:c201::4']


@pytest.mark.unit
def test_get_dkim_signing_domains(datadir):
    target_email = _load_email(str(datadir / 'emails/smtp.email.rfc822'))
    assert get_dkim_signing_domains(target_email) == ['gmail.com']

    # one observable per signature, deduplicated, and the d= tag is not confused with other tags
    multi = email.message_from_string(
        'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=first.example.com; s=sel;\r\n'
        'DKIM-Signature: v=1; a=rsa-sha256; d=Second.Example.COM; s=sel;\r\n'
        'DKIM-Signature: v=1; a=rsa-sha256; d=first.example.com; s=other;\r\n'
        '\r\nbody\r\n')
    assert get_dkim_signing_domains(multi) == ['first.example.com', 'second.example.com']

    assert get_dkim_signing_domains(email.message_from_string('Subject: x\r\n\r\nbody\r\n')) == []


@pytest.mark.unit
def test_get_sender_tenant_id(datadir):
    target_email = _load_email(str(datadir / 'emails/smtp.email.rfc822'))
    assert get_sender_tenant_id(target_email) == 'cfddba29-ca2a-450c-a415-595e7fcce8e5'

    # a non-GUID value is ignored rather than emitted
    assert get_sender_tenant_id(email.message_from_string(
        'X-MS-Exchange-CrossTenant-Id: not-a-guid\r\n\r\nbody\r\n')) is None

    assert get_sender_tenant_id(email.message_from_string('Subject: x\r\n\r\nbody\r\n')) is None


@pytest.mark.integration
def test_email_header_observables(root_analysis, datadir):
    """The new header observables land on the analysis tree end to end."""

    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(datadir / 'emails/smtp.email.rfc822'))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    file_observable = root_analysis.get_observable(file_observable.uuid)
    email_analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    assert isinstance(email_analysis, EmailAnalysis)
    email_analysis.load_details()

    def values(o_type):
        return sorted(_.value for _ in email_analysis.get_observables_by_type(o_type))

    assert values(F_EMAIL_FIRST_HOP_IP) == ['209.85.167.52']
    # the Received `from` token is the HELO; there is no reverse-DNS host in the parens
    assert values(F_EMAIL_FIRST_HOP_HELO) == ['mail-lf1-f52.google.com']
    assert values(F_EMAIL_FIRST_HOP_FROM) == []
    assert values(F_EMAIL_DKIM_SIGNING_DOMAIN) == ['gmail.com']
    assert values(F_EMAIL_SENDER_TENANT_ID) == ['cfddba29-ca2a-450c-a415-595e7fcce8e5']

    # the first hop IP observable must be the validating subclass, not DefaultObservable
    first_hop_ip = email_analysis.get_observables_by_type(F_EMAIL_FIRST_HOP_IP)[0]
    assert isinstance(first_hop_ip, EmailFirstHopIPObservable)


#
# message authentication + confirmed internal-spoof detection
#

@pytest.mark.unit
def test_parse_email_authentication():
    """SPF/DKIM/DMARC verdicts, composite auth, and the provider provenance flags."""

    target_email = email.message_from_string(
        'Authentication-Results: spf=fail (sender IP is 203.0.113.10) smtp.mailfrom=company.com;\r\n'
        ' dkim=none (message not signed) header.d=none;dmarc=fail action=oreject header.from=company.com;\r\n'
        'X-MS-Exchange-Organization-CompAuthRes: fail\r\n'
        'X-MS-Exchange-Organization-CompAuthReason: 000\r\n'
        'X-MS-Exchange-Organization-IsAnonymousDirectSend: True\r\n'
        'X-MS-Exchange-Organization-InternalOrgSender: True\r\n'
        'X-MS-Exchange-Organization-MessageDirectionality: Incoming\r\n'
        '\r\nbody\r\n')

    auth = parse_email_authentication(target_email)
    assert auth[KEY_SPF_RESULT] == 'fail'
    assert auth[KEY_DMARC_RESULT] == 'fail'
    assert auth[KEY_COMPAUTH_RESULT] == 'fail'
    assert auth[KEY_COMPAUTH_REASON] == '000'
    assert auth[KEY_IS_ANONYMOUS_DIRECT_SEND] is True

    # composite auth token inside Authentication-Results is used when the dedicated header is absent
    fallback = email.message_from_string(
        'Authentication-Results: spf=pass; dkim=pass; dmarc=pass action=none; compauth=pass reason=100\r\n'
        '\r\nbody\r\n')
    assert parse_email_authentication(fallback)[KEY_COMPAUTH_RESULT] == 'pass'

    # the Authentication-Results header carrying dmarc is preferred over an earlier relay's
    multi = email.message_from_string(
        'Authentication-Results: mx1.relay.example; spf=none\r\n'
        'Authentication-Results: protection.outlook.com; spf=fail; dmarc=fail action=oreject\r\n'
        '\r\nbody\r\n')
    assert parse_email_authentication(multi)[KEY_DMARC_RESULT] == 'fail'

    # a clean message resolves to no verdicts and no flags
    clean = parse_email_authentication(email.message_from_string('Subject: hi\r\n\r\nbody\r\n'))
    assert clean[KEY_COMPAUTH_RESULT] is None
    assert clean[KEY_IS_ANONYMOUS_DIRECT_SEND] is False


def _run_email_analyzer(root_analysis, path):
    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    file_observable = root_analysis.add_file_observable(str(path))
    file_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module('file_type', 'test_groups')
    engine.configuration_manager.enable_module('email_analyzer', 'test_groups')
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    file_observable = root_analysis.get_observable(file_observable.uuid)
    email_analysis = file_observable.get_and_load_analysis(EmailAnalysis)
    assert isinstance(email_analysis, EmailAnalysis)
    email_analysis.load_details()
    return file_observable, email_analysis


@pytest.mark.integration
def test_confirmed_internal_spoof_detection(root_analysis, datadir):
    """A forged-internal message that failed auth gets tagged and a detection point."""

    file_observable, email_analysis = _run_email_analyzer(
        root_analysis, datadir / 'emails/direct_send_spoof.email.rfc822')

    assert file_observable.has_tag(TAG_SPOOFED_INTERNAL)
    assert file_observable.has_tag(TAG_AUTHENTICATION_FAILED)
    assert file_observable.has_tag(TAG_ANONYMOUS_DIRECT_SEND)
    assert file_observable.detections, "expected a detection point on the spoofed email"

    # the parsed verdicts are stored in the per-message email details
    assert email_analysis.email[KEY_COMPAUTH_RESULT] == 'fail'
    assert email_analysis.email[KEY_DMARC_RESULT] == 'fail'
    assert email_analysis.email[KEY_IS_ANONYMOUS_DIRECT_SEND] is True

    # the confirming tenant GUID here would be an org/attributed header, which we deliberately
    # do NOT treat as the sender tenant -- so no email_sender_tenant_id observable is emitted
    assert email_analysis.get_observables_by_type(F_EMAIL_SENDER_TENANT_ID) == []


@pytest.mark.integration
def test_legitimate_inbound_not_flagged_as_spoof(root_analysis, datadir):
    """A normal inbound message from an external (non-managed) domain is not a spoof."""

    file_observable, _ = _run_email_analyzer(
        root_analysis, datadir / 'emails/smtp.email.rfc822')

    # From is @gmail.com (not a managed domain), so none of the spoof machinery fires
    assert not file_observable.has_tag(TAG_SPOOFED_INTERNAL)
    assert not file_observable.detections


#
# provider header configurability (non-Microsoft providers override the header names)
#

@pytest.mark.unit
def test_provider_headers_defaults_are_microsoft():
    """Out of the box the provider header lists are the Microsoft 365 names."""

    headers = EmailProviderHeaders()
    assert 'x-ms-exchange-organization-originalclientipaddress' in headers.first_hop_ip
    assert 'x-ms-exchange-crosstenant-id' in headers.sender_tenant_id
    assert headers.composite_auth_result == ['x-ms-exchange-organization-compauthres']


@pytest.mark.unit
def test_provider_headers_partial_override_keeps_other_defaults():
    """Overriding one list (as a deployment would) leaves the rest at their defaults."""

    headers = EmailProviderHeaders(first_hop_ip=['X-Received'])
    assert headers.first_hop_ip == ['X-Received']
    # untouched lists still hold the shipped Microsoft defaults
    assert 'x-ms-exchange-crosstenant-id' in headers.sender_tenant_id
    assert headers.composite_auth_result == ['x-ms-exchange-organization-compauthres']


@pytest.mark.unit
def test_resolve_first_hop_honors_configured_headers():
    """A provider that reports the sending IP in a different header is picked up via config."""

    # the custom header carries a bare IP distinct from the Received hop, so a result of
    # 203.0.113.99 can only have come from consulting the configured header. (The Received
    # hop uses a genuinely public IP; the fallback skips private/reserved ranges.)
    target_email = email.message_from_string(
        'X-Provider-Client-IP: 203.0.113.99\r\n'
        'Received: from mail.sender.example (209.85.167.52) by mx.company.com\r\n'
        '\r\nbody\r\n')

    # default Microsoft headers -> none present, falls back to the local-domain Received hop
    default_ip, _, _ = resolve_first_hop(target_email)
    assert default_ip == '209.85.167.52'

    # configured to trust X-Provider-Client-IP -> that header's value wins
    config_ip, _, _ = resolve_first_hop(target_email, ip_headers=['x-provider-client-ip'])
    assert config_ip == '203.0.113.99'


@pytest.mark.unit
def test_get_sender_tenant_id_honors_configured_headers():
    target_email = email.message_from_string(
        'X-Provider-Tenant: 7a53b4fc-e87d-4c46-9972-0570ac271b27\r\n\r\nbody\r\n')

    # not one of the default Microsoft headers
    assert get_sender_tenant_id(target_email) is None
    assert get_sender_tenant_id(target_email, tenant_headers=['x-provider-tenant']) == \
        '7a53b4fc-e87d-4c46-9972-0570ac271b27'


@pytest.mark.unit
def test_parse_email_authentication_graceful_when_headers_absent_from_config():
    """A provider lacking a concept (empty header list) yields None without error."""

    # a message that DOES carry Microsoft composite-auth headers...
    target_email = email.message_from_string(
        'Authentication-Results: spf=fail; dmarc=fail action=oreject\r\n'
        'X-MS-Exchange-Organization-CompAuthRes: fail\r\n'
        'X-MS-Exchange-Organization-IsAnonymousDirectSend: True\r\n'
        '\r\nbody\r\n')

    # ...parsed for a provider configured with NO composite-auth / direct-send headers
    provider = EmailProviderHeaders(
        composite_auth_result=[],
        composite_auth_reason=[],
        anonymous_direct_send=[],
        internal_org_sender=[],
        message_directionality=[],
    )
    auth = parse_email_authentication(target_email, provider)
    assert auth[KEY_COMPAUTH_RESULT] is None          # header ignored per config, no error
    assert auth[KEY_IS_ANONYMOUS_DIRECT_SEND] is False
    # the RFC-standard Authentication-Results parsing is provider-neutral and still works
    assert auth[KEY_DMARC_RESULT] == 'fail'


@pytest.mark.unit
def test_email_analyzer_config_exposes_provider_headers_default():
    """The loaded module config surfaces provider_headers with the Microsoft defaults."""

    config = get_analysis_module_config('email_analyzer')
    assert isinstance(config, EmailAnalyzerConfig)
    assert 'x-ms-exchange-organization-originalclientipaddress' in config.provider_headers.first_hop_ip
    assert 'x-ms-exchange-crosstenant-id' in config.provider_headers.sender_tenant_id


@pytest.mark.unit
def test_extract_first_hop_ip_structured_value():
    """A structured header (tenant-relayed mail) yields the connecting IP, not junk."""

    from saq.modules.email.rfc822 import extract_first_hop_ip

    # bare / bracketed values keep working (fast path)
    assert extract_first_hop_ip('135.125.140.186') == '135.125.140.186'
    assert extract_first_hop_ip('[135.125.140.186]') == '135.125.140.186'
    assert extract_first_hop_ip('2a01:111:f403:c101::7') == '2a01:111:f403:c101::7'

    # X-MS-Exchange-Organization-OriginalAttributedTenantConnectingIp form: the GUID must
    # not be mistaken for an IP, and the connecting Ip= wins over the trailing Helo= loopback
    structured = 'TenantId=39f8e1f5-7405-4ce3-be3f-3712fbf3c157;Ip=[135.125.140.186];Helo=[[127.0.0.1]]'
    assert extract_first_hop_ip(structured) == '135.125.140.186'

    assert extract_first_hop_ip('no ip here') is None


@pytest.mark.unit
def test_resolve_first_hop_prefers_tenant_connecting_ip_over_internal_client_ip():
    """On tenant-relayed mail the true external ingress beats the Microsoft-internal hop.

    OriginalClientIPAddress can be a Microsoft datacenter IPv6 when a message is relayed
    tenant-to-tenant; OriginalAttributedTenantConnectingIp carries the real external IP and
    is listed first, so it wins.
    """
    target_email = email.message_from_string(
        'X-MS-Exchange-Organization-OriginalAttributedTenantConnectingIp: '
        'TenantId=39f8e1f5-7405-4ce3-be3f-3712fbf3c157;Ip=[135.125.140.186];Helo=[[127.0.0.1]]\r\n'
        'X-MS-Exchange-Organization-OriginalClientIPAddress: 2a01:111:f403:c101::7\r\n'
        'Received: from [127.0.0.1] (135.125.140.186) by mx.company.com\r\n'
        '\r\nbody\r\n')

    hop_ip, hop_helo, hop_from = resolve_first_hop(target_email)
    assert hop_ip == '135.125.140.186'
    # the Received `from` token is a bracketed loopback literal: not a hostname, so it is not
    # first_hop_from, but it IS the (spoofed) HELO the client presented
    assert hop_from is None
    assert hop_helo == '127.0.0.1'


@pytest.mark.unit
def test_resolve_first_hop_address_literal_helo_becomes_helo():
    """An address-literal HELO (spoofed `[127.0.0.1]`) is the helo, not first_hop_from."""

    target_email = email.message_from_string(
        'X-Sender-IP: 203.0.113.5\r\n'
        'Received: from [127.0.0.1] (203.0.113.5) by mx.company.com\r\n'
        '\r\nbody\r\n')

    hop_ip, hop_helo, hop_from = resolve_first_hop(target_email)
    assert hop_ip == '203.0.113.5'
    assert hop_helo == '127.0.0.1'
    assert hop_from is None
