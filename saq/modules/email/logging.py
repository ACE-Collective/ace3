from datetime import datetime
import json
import logging
import os

from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.analysis.search import recurse_tree
from saq.configuration.config import get_config_value
from saq.constants import CONFIG_ELK_LOGGING, CONFIG_ELK_LOGGING_DIR, CONFIG_SPLUNK_LOGGING, CONFIG_SPLUNK_LOGGING_DIR, DIRECTIVE_ORIGINAL_EMAIL, F_FILE, F_URL, AnalysisExecutionResult
from saq.database.pool import get_db_connection
from saq.database.retry import execute_with_retry
from saq.email import normalize_email_address
from saq.environment import get_base_dir, get_data_dir
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule


class EmailHistoryRecord:
    """Utility class to add extra fields not present in the splunk logs."""

    def __init__(self, details):
        self.details = details

    #def __getattr__(self, name):
        #return self.details[name]
    
    def __getitem__(self, key):
        return self.details[key]

    @property
    def md5(self):
        file_name = os.path.basename(self.details['archive_path'])
        md5, ext = os.path.splitext(file_name)
        return md5

class EmailLoggingAnalysis(Analysis):
    pass

class EmailLoggingAnalyzer(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # splunk log settings
        self.splunk_log_enabled = self.config.getboolean('splunk_log_enabled')
        self.splunk_log_dir = os.path.join(get_data_dir(), get_config_value(CONFIG_SPLUNK_LOGGING, CONFIG_SPLUNK_LOGGING_DIR), 
                                           self.config['splunk_log_subdir'])

        # JSON log settings (for elasticsearch)
        self.json_log_enabled = self.config.getboolean('json_log_enabled')
        self.json_log_path_format = self.config['json_log_path_format']

        # brocess log settings
        self.update_brocess = self.config.getboolean('update_brocess')

    def verify_environment(self):
        self.verify_config_exists('splunk_log_subdir')
        self.create_required_directory(self.splunk_log_dir)
        
    @property
    def generated_analysis_type(self):
        return EmailLoggingAnalysis

    @property
    def valid_observable_types(self):
        return None

    def execute_analysis(self, target) -> AnalysisExecutionResult:
        return AnalysisExecutionResult.COMPLETED

    def execute_post_analysis(self):

        # process each "original email" in the analysis
        for f in self.get_root().get_observables_by_type(F_FILE):
            if not f.has_directive(DIRECTIVE_ORIGINAL_EMAIL):
                continue

            self.process_email(f)

        return True

    def process_email(self, email_file):

        from saq.modules.email.rfc822 import EmailAnalysis
        from saq.modules.email.archive import EmailArchiveResults

        analysis = email_file.get_and_load_analysis(EmailAnalysis)
        if not analysis:
            # XXX hack - make MUCH better support for whitelisting :-(
            if not email_file.has_tag('whitelisted'):
                logging.warning("missing EmailAnalysis for {} - not logging".format(email_file))
            return

        if not analysis.email:
            logging.warning("missing analysis.email for {} - not logging".format(email_file))
            return

        # has this been whitelisted?
        if email_file.has_tag('whitelisted'):
            return

        if not analysis.log_entry:
            logging.warning("missing log entry for {}".format(email_file))
            return

        logging.debug("creating export logging for {}".format(email_file))

        # look for url extracted as well
        extracted_urls = []

        # find all urls starting from this analysis
        def _callback(target):
            nonlocal extracted_urls
            if isinstance(target, Observable) and target.type == F_URL:
                extracted_urls.append(target.value)

        recurse_tree(analysis, _callback)
        # remove duplicates
        extracted_urls = list(set(extracted_urls))

        # since we only extract urls from emails we just find them all in the entire analysis tree
        #for url_extraction in self.get_root().all_analysis:
            #if not isinstance(url_extraction, URLExtractionAnalysis):
                #continue

            #if url_extraction.details is not None:
                #extracted_urls.extend(url_extraction.details)

        # log where we ended up archiving the email
        archive_path = None
        archive_results = email_file.get_and_load_analysis(EmailArchiveResults)
        if archive_results:
            archive_path = archive_results.archive_path

        #url_extraction = email_file.get_and_load_analysis(URLExtractionAnalysis)
        #if url_extraction and url_extraction.details:
            # get all the URLs extracted
            #extracted_urls = url_extraction.details

        # so all we need to do now is figure out how to write the data from
        # multiple processes to the same place without collision
        entry = analysis.log_entry.copy()
        entry.update({'extracted_urls': extracted_urls})
        entry.update({'archive_path': None if archive_path is None else os.path.relpath(archive_path, start=get_base_dir())})

        try:
            self.export_to_splunk(entry.copy())
        except Exception as e:
            logging.error("unable to create splunk log export for {}: {}".format(email_file, e))

        try:
            self.export_to_es(entry.copy())
        except Exception as e:
            logging.error("unable to create elasticsearch log export for {}: {}".format(email_file, e))

        try:
            self.export_to_brocess(entry.copy())
        except Exception as e:
            logging.error("unable to create brocess data export for {}: {}".format(email_file, e))

        return True

    def export_to_splunk(self, entry):
        """Exports the logging information to a directory where splunk can pick it up."""
        if not self.splunk_log_enabled:
            return

        entry_data = []

        # we have to have splunk extracted urls into a separate index
        extracted_urls = entry['extracted_urls']
        entry['extracted_urls'] = []
        entry['headers'] = 'temporarily removed'

        # convert the date into a timestamp for splunk
        entry['date'] = str(datetime.strptime(entry['date'], '%Y-%m-%d %H:%M:%S.%f %z').timestamp())

        # for splunk we need to sort the keys alphabetically
        entry_keys = list(entry.keys())

        # there's a couple fields WE don't log to splunk because of internal splunk issues
        # date,attachment_count,attachment_hashes,attachment_names,attachment_sizes,attachment_types,bcc,cc
        # env_mail_from,env_rcpt_to,extracted_urls,first_received,headers,last_received,mail_from,mail_to
        # message_id,originating_ip,path,reply_to,size,subject,user_agent,archive_path,x_mailer
        entry_keys.remove('thread_topic')
        entry_keys.remove('thread_index')
        entry_keys.remove('refereneces')
        entry_keys.remove('x_sender')

        # NOTE we need to make the date first
        # NOTE we also need to make archive_path last :(
        entry_keys.remove('date')
        entry_keys.remove('archive_path')
        entry_keys.remove('x_mailer')
        entry_keys = sorted(entry_keys)
        entry_keys.insert(0, 'date')
        entry_keys.append('archive_path')
        entry_keys.append('x_mailer')

        # we essentially document the fields in this file
        # XXX do we need to do this?
        fields_file = os.path.join(self.splunk_log_dir, 'fields')
        if not os.path.exists(fields_file):
            with open(fields_file, 'w') as fp:
                fp.write(','.join(entry_keys))

        for field in entry_keys:
            # items that are lists are combined with UNIT SEPARATOR
            if isinstance(entry[field], list):
                entry_data.append('\x1F'.join(map(str, entry[field])))
            else:
                entry_data.append(str(entry[field]) if entry[field] else '')

        def _esc(s):
            return str(s).replace('\n', '').replace('\r', '')

        # fields are separated with RECORD SEPARATOR and saved to files with pid appended
        with open(os.path.join(self.splunk_log_dir, 'smtp-{}.{}.log'.format(
                               datetime.now().strftime('%Y-%m-%d-%H'),
                               os.getpid())), 'a') as fp:
            fp.write('{}\n'.format(_esc('\x1e'.join(entry_data))))

        # we write extracted URLs into a separate log source in splunk
        # each URL gets it's own log entry

        if entry['message_id']:
            with open(os.path.join(self.splunk_log_dir, 'url-{}.{}.log'.format(
                                   datetime.now().strftime('%Y-%m-%d-%H'),
                                   os.getpid())), 'a') as fp:

                logged_urls = set()
                for url in extracted_urls:
                    # don't log dupes
                    if url in logged_urls:
                        continue

                    logged_urls.add(url)
                    entry_data = [ entry['date'], entry['message_id'], url ]
                    fp.write('{}\n'.format(_esc('\x1e'.join(entry_data))))

    def export_to_es(self, entry):
        """Create the ElasticSearch log entry."""

        if not self.json_log_enabled:
            return

        target_path = os.path.join(get_data_dir(), get_config_value(CONFIG_ELK_LOGGING, CONFIG_ELK_LOGGING_DIR), 
                                   datetime.now().strftime(self.json_log_path_format)).format(pid=os.getpid())

        # has the current JSON path
        target_dir = os.path.dirname(target_path)
        if not os.path.exists(target_dir):
            try:
                logging.debug("creating json logging directory {}".format(target_dir))
                os.makedirs(target_dir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(target_dir, e))
                return

        with open(target_path, 'a') as fp:
            fp.write(json.dumps(entry))
            fp.write('\n')

    def export_to_brocess(self, entry):
        if not self.update_brocess:
            return

        # are we updating the brocess database?
        mail_from = normalize_email_address(entry['mail_from'])
        if not mail_from:
            return

        logging.debug("updating brocess for {}".format(mail_from))

        try:
            with get_db_connection(name='brocess') as db:
                c = db.cursor()
                for email_address in entry['env_rcpt_to']:
                    email_address = normalize_email_address(email_address)
                    if not email_address:
                        continue

                    sql = """INSERT INTO smtplog ( source, destination, numconnections, firstconnectdate )
                             VALUES (%s, %s, 1, UNIX_TIMESTAMP(NOW()))
                             ON DUPLICATE KEY UPDATE numconnections = numconnections + 1"""
                    params = (mail_from[:255], email_address[:255])
                    execute_with_retry(db, c, sql, params)

                db.commit()

        except Exception as e:
            logging.error("unable to update brocess: {}".format(e))
            report_exception()
