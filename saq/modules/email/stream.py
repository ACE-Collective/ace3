import gzip
import logging
import os
import re
import shutil
import socket
from subprocess import PIPE, Popen
from typing import Type
from pydantic import Field
from saq.analysis.analysis import Analysis
from saq.constants import DIRECTIVE_ARCHIVE, F_FILE, AnalysisExecutionResult
from saq.crypto import encrypt
from saq.environment import get_data_dir
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.email.constants import KEY_ENVELOPES, KEY_ENVELOPES_MAIL_FROM, KEY_ENVELOPES_RCPT_TO, KEY_SMTP_FILES
from saq.observables.file import FileObservable

pattern_brotex_connection = re.compile(r'^connection\.([0-9]+)\.parsed$')
pattern_brotex_package = re.compile(r'(C[^\.]+)\.smtp\.tar$')
pattern_brotex_missing_stream_package = re.compile(r'(C[^\.]+)\.smtp\.tar\.[0-9]+\.missing_stream$')
# _162.128.171.76:58771-162.128.125.36:25_.stream
pattern_brotex_stream = re.compile(
r'^_[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}'
'-'
r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}_\.stream$')


class BrotexSMTPStreamArchiveConfig(AnalysisModuleConfig):
    archive_dir: str = Field(..., description="The directory to contain the archived streams (relative to DATA_DIR).")

class SMTPStreamAnalyzerConfig(AnalysisModuleConfig):
    protocol_scan_line_count: int = Field(..., description="The number of lines to scan at the beginning of the file to detect SMTP protocol data.")


class BrotexSMTPStreamArchiveResults(Analysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            "archive_path": None
        }

    @property
    def archive_path(self):
        return self.details["archive_path"]

    @archive_path.setter
    def archive_path(self, value):
        self.details["archive_path"] = value

    def generate_summary(self):
        if not self.archive_path:
            return None

        return "Archive Path - {}".format(self.archive_path)

class BrotexSMTPStreamArchiveAction(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return BrotexSMTPStreamArchiveConfig

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hostname = socket.gethostname().lower()

    def verify_environment(self):
        self.verify_path_exists(self.config.archive_dir)

    @property
    def generated_analysis_type(self):
        return BrotexSMTPStreamArchiveResults

    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def required_directives(self):
        return [ DIRECTIVE_ARCHIVE ]

    def execute_analysis(self, _file) -> AnalysisExecutionResult:
        assert isinstance(_file, FileObservable)
        # is this a brotex package?
        m = pattern_brotex_package.match(_file.file_path)
        if not m:
            logging.debug("{} does not appear to be a brotex smtp package".format(_file))
            return AnalysisExecutionResult.COMPLETED

        connection_id = m.group(1)
        logging.debug("archiving bro smtp connection {} from {}".format(connection_id, _file))

        # where do we put the file?
        archive_dir = os.path.join(get_data_dir(), self.config.archive_dir, self.hostname, connection_id[0:3])
        if not os.path.isdir(archive_dir):
            logging.debug("creating archive directory {}".format(archive_dir))

            try:
                os.makedirs(archive_dir)
            except:
                # it might have already been created by another process
                # mkdir is an atomic operation (FYI)
                if not os.path.isdir(archive_dir):
                    raise Exception("unable to create archive directory {}: {}".format(archive_dir, str(e)))

        analysis = self.create_analysis(_file)
        assert isinstance(analysis, BrotexSMTPStreamArchiveResults)
        source_path = _file.full_path
        archive_path = os.path.join(archive_dir, _file.value) # <-- sha256 hash value OK
        if os.path.exists('{}.gz.e'.format(archive_path)):
            logging.warning("archive path {} already exists".format('{}.gz.e'.format(archive_path)))
            analysis.archive_path = archive_path
            return AnalysisExecutionResult.COMPLETED
        else:
            shutil.copy2(source_path, archive_path)

        archive_path += '.gz'

        # compress the data
        logging.debug("compressing {}".format(archive_path))
        try:
            with open(source_path, 'rb') as fp_in:
                with gzip.open(archive_path, 'wb') as fp_out:
                    shutil.copyfileobj(fp_in, fp_out)

        except Exception as e:
            logging.error("compression failed for {}: {}".format(archive_path, e))

        if not os.path.exists(archive_path):
            raise Exception("compression failed for {}".format(archive_path))

        # encrypt the archive file
        encrypted_file = '{}.e'.format(archive_path)

        try:
            encrypt(archive_path, encrypted_file)
        except Exception as e:
            logging.error("unable to encrypt archived stream {}: {}".format(archive_path, e))

        if os.path.exists(encrypted_file):
            logging.debug("encrypted {}".format(archive_path))
            try:
                os.remove(archive_path)
            except Exception as e:
                logging.error("unable to delete unencrypted archive file {}: {}".format(archive_path, e))
                raise e
        else:
            raise Exception("expected encrypted output file {} does not exist".format(encrypted_file))

        logging.debug("archived stream {} to {}".format(source_path, encrypted_file))

        analysis.archive_path = archive_path
        return AnalysisExecutionResult.COMPLETED

class BrotexSMTPPackageAnalysis(Analysis):

    KEY_CONNECTION_ID = 'connection_id'
    KEY_SMTP_STREAM = 'smtp_stream'
    KEY_MESSAGE_COUNT = 'message_count'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            BrotexSMTPPackageAnalysis.KEY_CONNECTION_ID: None,
            BrotexSMTPPackageAnalysis.KEY_SMTP_STREAM: None,
            BrotexSMTPPackageAnalysis.KEY_MESSAGE_COUNT: 0 }

    @property
    def connection_id(self):
        if self.details and BrotexSMTPPackageAnalysis.KEY_CONNECTION_ID in self.details:
            return self.details[BrotexSMTPPackageAnalysis.KEY_CONNECTION_ID]

        return None

    @connection_id.setter
    def connection_id(self, value):
        self.details[BrotexSMTPPackageAnalysis.KEY_CONNECTION_ID] = value

    @property
    def smtp_stream(self):
        if self.details and BrotexSMTPPackageAnalysis.KEY_SMTP_STREAM in self.details:
            return self.details[BrotexSMTPPackageAnalysis.KEY_SMTP_STREAM]

        return None

    @smtp_stream.setter
    def smtp_stream(self, value):
        self.details[BrotexSMTPPackageAnalysis.KEY_SMTP_STREAM] = value

    @property
    def message_count(self):
        if self.details and BrotexSMTPPackageAnalysis.KEY_MESSAGE_COUNT in self.details:
            return self.details[BrotexSMTPPackageAnalysis.KEY_MESSAGE_COUNT]

        return 0

    @message_count.setter
    def message_count(self, value):
        assert isinstance(value, int)
        self.details[BrotexSMTPPackageAnalysis.KEY_MESSAGE_COUNT] = value

    def generate_summary(self):
        if not self.connection_id:
            return None

        prefix = "Brotex SMTP Package Analysis -"

        if self.smtp_stream:
            return "{} {}".format(prefix, self.smtp_stream)

        return "{} missing stream ({} emails detected)".format(prefix, self.message_count)

class BrotexSMTPPackageAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return BrotexSMTPPackageAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file) -> AnalysisExecutionResult:
        assert isinstance(_file, FileObservable)
        from saq.modules.email.rfc822 import EmailAnalyzer

        # is this a brotex package?
        m = pattern_brotex_package.match(_file.file_path)
        if not m:
            logging.debug("{} does not appear to be a brotex smtp package".format(_file))
            return AnalysisExecutionResult.COMPLETED

        logging.debug("{} is a valid brotex smtp package".format(_file))
        analysis = self.create_analysis(_file)
        assert isinstance(analysis, BrotexSMTPPackageAnalysis)
        analysis.connection_id = m.group(1)

        # view the contents of the package
        file_path = _file.full_path
        _stdout = _stderr = None

        try:
            p = Popen(['tar', 'tf', file_path], stdout=PIPE, stderr=PIPE, universal_newlines=True)
            _stdout, _stderr = p.communicate() # meh
            p.wait()
        except Exception as e:
            logging.error("unable to view brotex package {}: {}".format(_file, e))
            report_exception()
            return AnalysisExecutionResult.COMPLETED

        if _stderr:
            logging.warning("tar reported errors on {}: {}".format(_file, _stderr)) # TODO fold stderr newlines

        #
        # basically the issue here is that bro sometimes does not record the TCP stream like we want it to
        # but it's still able to parse the SMTP data and extract the files
        # we want to do the best with what we've got
        #
            
        # parse the tar file listing to see if it has an smtp stream file
        smtp_stream_file = None

        for relative_path in _stdout.split('\n'):
            if pattern_brotex_stream.match(os.path.basename(relative_path)):
                smtp_stream_file = relative_path
                break # this is all we need
            
            if pattern_brotex_connection.match(os.path.basename(relative_path)):
                connection_file = relative_path
                continue

        # did we get the stream data?
        #while False: #smtp_stream_file:
        while smtp_stream_file:
            # extract *only* that file
            p = Popen(['tar', 'xf', file_path, '-C', self.get_root().storage_dir, smtp_stream_file], 
                      stdout=PIPE, stderr=PIPE, universal_newlines=True)
            stdout, stderr = p.communicate()
            p.wait()

            if p.returncode:
                logging.warning("unable to extract {} from {} (tar returned error code {}".format(
                                smtp_stream_file, _file, p.returncode))
                smtp_stream_file = None
                break

            if stderr:
                logging.warning("tar reported errors on {}: {}".format(_file, stderr))

            # add the extracted smtp stream file as an observable and let the SMTPStreamAnalysis module do it's work
            smtp_observable = analysis.add_file_observable(smtp_stream_file)
            if smtp_observable:
                smtp_observable.add_yara_meta("type", "network.smtp")

            analysis.smtp_stream = smtp_stream_file
            return AnalysisExecutionResult.COMPLETED

        # -----------------------------------------------------------------------------------------------------------
        # 
        # otherwise bro didn't get the stream file so we need to make do with what we've got
        #

        logging.debug("stream file was not detected in {}".format(_file))

        brotex_dir = '{}.brotex'.format(os.path.join(self.get_root().file_dir, _file.file_path))
        if not os.path.isdir(brotex_dir):
            try:
                os.mkdir(brotex_dir)
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(brotex_dir, e))
                return AnalysisExecutionResult.COMPLETED

        # extract all the things into the brotex_dir
        p = Popen(['tar', 'xf', file_path, '-C', brotex_dir], 
                  stdout=PIPE, stderr=PIPE, universal_newlines=True)
        stdout, stderr = p.communicate()
        p.wait()

        if p.returncode:
                logging.warning("unable to extract files from {} (tar returned error code {}".format(
                                _file, p.returncode))
                return AnalysisExecutionResult.COMPLETED

        if stderr:
            logging.warning("tar reported errors on {}: {}".format(_file, stderr))

        # iterate over all the extracted files
        # map message numbers to the connection file
        connection_files = {} # key = message_number, value = path to connection file
        for dirpath, dirnames, filenames in os.walk(brotex_dir):
            for file_name in filenames:
                m = pattern_brotex_connection.match(file_name)
                if m:
                    # keep track of the largest trans_depth
                    trans_depth = m.group(1)
                    connection_files[trans_depth] = os.path.join(dirpath, file_name)

        # create a new tar file for each individual message (to be parsed by EmailAnalyzer)
        for message_number in connection_files.keys():
            missing_stream_file = '{}.{}.missing_stream'.format(_file.file_path, message_number)
            missing_stream_path = os.path.join(self.get_root().storage_dir, missing_stream_file)
            logging.debug("creating missing stream archive {}".format(missing_stream_path))
            if os.path.exists(missing_stream_path):
                logging.warning("missing stream file {} already exists".format(missing_stream_path))
                continue

            relative_dir = os.path.dirname(connection_files[message_number])
            logging.debug("relative_dir = {}".format(relative_dir))

            # we tar up the connection info file and any files under the message_N subdirectory
            p = Popen(['tar', '-C', relative_dir, '-c', '-f', missing_stream_path, 
                        os.path.basename(connection_files[message_number]), 
                       'message_{}/'.format(message_number)], stdout=PIPE, stderr=PIPE)
            _stdout, _stderr = p.communicate()
            p.wait()

            if p.returncode != 0:
                logging.error("tar returned error code {} when creating {}".format(p.returncode, missing_stream_path))
                continue

            if _stderr:
                logging.warning("tar printing output to stderr when creating {}: {}".format(missing_stream_path, _stderr))

            # this by itself gets added as a file observable that will later get parsed by EmailAnalyzer
            observable = analysis.add_file_observable(missing_stream_file)
            if observable:
                observable.limited_analysis = [ EmailAnalyzer.__name__ ]
                observable.add_yara_meta("type", "email")
            analysis.message_count += 1 

        return AnalysisExecutionResult.COMPLETED

class SMTPStreamAnalysis(Analysis):
    """What are the emails contained in this SMTP stream?"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_SMTP_FILES: [],
            KEY_ENVELOPES: {}, # key = smtp_file, value = {} (keys = env_mail_from, [env_rcpt_to])
        }

    @property
    def smtp_files(self):
        if not self.details:
            return None

        if KEY_SMTP_FILES not in self.details:
            return None

        return self.details[KEY_SMTP_FILES]

    @property
    def envelopes(self):
        if not self.details:
            return None

        if KEY_ENVELOPES not in self.details:
            return None

        return self.details[KEY_ENVELOPES]

    def generate_summary(self):
        if not self.smtp_files:
            return None

        return "SMTP Stream Analysis ({} emails)".format(len(self.smtp_files))

class SMTPStreamAnalyzer(AnalysisModule):
    """Parses SMTP protocol traffic for RFC 822 messages."""
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return SMTPStreamAnalyzerConfig

    @property
    def generated_analysis_type(self):
        return SMTPStreamAnalysis

    @property
    def valid_observable_types(self):
        return F_FILE

    def execute_analysis(self, _file) -> AnalysisExecutionResult:
        assert isinstance(_file, FileObservable)

        # is this not a brotex file?
        if pattern_brotex_package.match(_file.file_name):
            return AnalysisExecutionResult.COMPLETED

        # is this a smtp protocol session?
        _path = _file.full_path
        line_number = 1
        has_mail_from = False
        has_rcpt_to = False
        has_data = False

        if not os.path.exists(_path):
            logging.warning("file {} does not exist".format(_path))
            return AnalysisExecutionResult.COMPLETED

        # read the first N lines looking for required SMTP protocol data
        with open(_path, 'rb') as fp:
            while line_number < self.config.protocol_scan_line_count:
                line = fp.readline()
                has_mail_from |= line.startswith(b'MAIL FROM:')
                has_rcpt_to |= line.startswith(b'RCPT TO:')
                has_data |= line.strip() == b'DATA'
                line_number += 1

                if has_mail_from and has_rcpt_to and has_data:
                    break

        if not (has_mail_from and has_rcpt_to and has_data):
            logging.debug("{} does not appear to be an smtp stream".format(_file))
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(_file)

        # if this is an SMTP stream then we want to archive it
        _file.add_directive(DIRECTIVE_ARCHIVE)

        logging.debug("parsing smtp stream file {}".format(_file))

        # parse the SMTP stream(s)
        env_mail_from = None
        env_rcpt_to = []
        rfc822_index = 0
        current_fp = None
        current_rfc822_path = None

        def _complete_stream():
            nonlocal current_fp, current_rfc822_path, rfc822_index, env_mail_from, env_rcpt_to # TIL? :-D
            current_fp.close()
            current_fp = None
            logging.debug("finished writing {}".format(current_rfc822_path))

            rel_path = os.path.relpath(current_rfc822_path, start=self.get_root().storage_dir)
            analysis.smtp_files.append(rel_path)
            email_observable = analysis.add_file_observable(rel_path)
            if email_observable:
                email_observable.add_yara_meta("type", "email")
            analysis.envelopes[rel_path] = {}
            analysis.envelopes[rel_path][KEY_ENVELOPES_MAIL_FROM] = env_mail_from
            analysis.envelopes[rel_path][KEY_ENVELOPES_RCPT_TO] = env_rcpt_to

            current_rfc822_path = None
            env_mail_from = None
            env_rcpt_to = []
            rfc822_index += 1

        with open(_path, 'rb') as fp:
            while True:
                line = fp.readline()
                if line == b'':
                    if current_fp:
                        logging.info("incomplete smtp stream file {}".format(_file))
                        _complete_stream()

                    break

                # are we saving a mail to disk?
                if current_fp:
                    if line.strip() == b'.':
                        _complete_stream()
                        continue
                        
                    # see https://www.ietf.org/rfc/rfc2821.txt section 4.5.2
                    if line.startswith(b'.') and line.strip() != b'.':
                        line = line[1:]

                    current_fp.write(line)
                    continue

                if not env_mail_from:
                    if line.startswith(b'MAIL FROM:'):
                        _, env_mail_from = line.decode().strip().split(':', 1)
                        logging.debug("got env_mail_from {} from {}".format(env_mail_from, _file))
                        continue

                if not env_rcpt_to:
                    if line.startswith(b'RCPT TO:'):
                        _, _env_rcpt_to = line.decode().strip().split(':', 1)
                        logging.debug("got env_rcpt_to {} from {}".format(_env_rcpt_to, _file))
                        env_rcpt_to.append(_env_rcpt_to)
                        continue

                if not current_fp:
                    if line.strip() != b'DATA':
                        continue

                # at this point we're at the DATA command
                if not env_mail_from:
                    logging.warning("missing MAIL FROM in {} for message {}".format(_file, rfc822_index))

                if not env_rcpt_to:
                    logging.warning("missing RCPT TO in {} for message {}".format(_file, rfc822_index))

                current_rfc822_path = os.path.join(self.get_root().storage_dir, '{}.rfc822_{:03}'.format(
                                                   _file.file_name, rfc822_index))
                current_fp = open(current_rfc822_path, 'wb')
                logging.debug("saving smtp stream {} from {}".format(current_rfc822_path, _file))

                # is the next line the expected 354 message?
                line = fp.readline()
                if line.startswith(b'354'):
                    # this is skipped
                    continue

                current_fp.write(line)
                continue

        return AnalysisExecutionResult.COMPLETED