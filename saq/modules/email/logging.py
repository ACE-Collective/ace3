from datetime import datetime
from typing import Optional, Type
from pydantic import BaseModel, Field
import logging
import os

from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.analysis.search import recurse_tree
from saq.constants import DIRECTIVE_ORIGINAL_EMAIL, F_FILE, F_URL, AnalysisExecutionResult
from saq.database.pool import get_db_connection
from saq.database.retry import execute_with_retry
from saq.email import normalize_email_address
from saq.environment import get_base_dir
from saq.error.reporting import report_exception
from saq.modules import AnalysisModule

from fluent import sender

from saq.modules.config import AnalysisModuleConfig

class FluentBitTags(BaseModel):
    main: str = Field(..., description="the main tag for fluent-bit logging")
    urls: Optional[str] = Field(default=None, description="(optional) send extracted urls to a separate log source")
    headers: Optional[str] = Field(default=None, description="(optional) send extracted headers to a separate log source")
    lookalike: Optional[str] = Field(default=None, description="(optional) send look-a-like domain telemetry to a separate log source")

class EmailLoggingConfig(AnalysisModuleConfig):
    brocess_logging_enabled: bool = Field(..., description="whether to enable brocess logging")
    thread_recording_enabled: bool = Field(default=False, description="whether to record email conversation (thread) data to brocess")
    lookalike_telemetry_enabled: bool = Field(default=False, description="whether to compute and emit look-a-like domain telemetry")
    fluent_bit_tags: FluentBitTags = Field(..., description="the tags to use for fluent-bit logging")
    fluent_bit_logging_enabled: bool = Field(..., description="whether to enable fluent-bit logging")
    fluent_bit_hostname: str = Field(..., description="the hostname of the fluent-bit server")
    fluent_bit_port: int = Field(..., description="the port of the fluent-bit server")

class EmailLoggingAnalysis(Analysis):
    pass

class EmailLoggingAnalyzer(AnalysisModule):
    config: EmailLoggingConfig

    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return EmailLoggingConfig

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # brocess log settings
        self.brocess_logging_enabled = self.config.brocess_logging_enabled
        self.fluent_bit_main_sender: Optional[sender.FluentSender] = None
        self.fluent_bit_urls_sender: Optional[sender.FluentSender] = None
        self.fluent_bit_headers_sender: Optional[sender.FluentSender] = None
        self.fluent_bit_lookalike_sender: Optional[sender.FluentSender] = None

        if self.config.fluent_bit_logging_enabled:
            self.fluent_bit_main_sender = sender.FluentSender(
                self.config.fluent_bit_tags.main,
                host=self.config.fluent_bit_hostname,
                port=self.config.fluent_bit_port)

            if self.config.fluent_bit_tags.urls:
                self.fluent_bit_urls_sender = sender.FluentSender(
                    self.config.fluent_bit_tags.urls,
                    host=self.config.fluent_bit_hostname,
                    port=self.config.fluent_bit_port)

            if self.config.fluent_bit_tags.headers:
                self.fluent_bit_headers_sender = sender.FluentSender(
                    self.config.fluent_bit_tags.headers,
                    host=self.config.fluent_bit_hostname)

            if self.config.fluent_bit_tags.lookalike:
                self.fluent_bit_lookalike_sender = sender.FluentSender(
                    self.config.fluent_bit_tags.lookalike,
                    host=self.config.fluent_bit_hostname,
                    port=self.config.fluent_bit_port)

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

        if self.config.brocess_logging_enabled:
            try:
                self.export_to_brocess(entry.copy())
            except Exception as e:
                logging.error(f"unable to create brocess log export for {email_file}: {e}")
                report_exception()

        if self.config.fluent_bit_logging_enabled:
            try:
                self.export_to_fluent_bit(entry.copy())
            except Exception as e:
                logging.error(f"unable to create fluent-bit log export for {email_file}: {e}")
                report_exception()

        if self.config.thread_recording_enabled or self.config.lookalike_telemetry_enabled:
            try:
                self.export_lookalike_telemetry(entry.copy(), analysis)
            except Exception as e:
                logging.error(f"unable to create lookalike telemetry for {email_file}: {e}")
                report_exception()

        return True

    def export_to_fluent_bit(self, entry: dict) -> bool:
        # convert the date into a timestamp for splunk
        entry["timestamp"] = str(datetime.strptime(entry["date"], '%Y-%m-%d %H:%M:%S.%f %z').timestamp())
        if not entry.get("message_id"):
            logging.warning(f"missing message_id for {entry}")
        else:
            # are we sending extracted urls to a separate log source?
            if self.fluent_bit_urls_sender:
                for url in entry["extracted_urls"]:
                    url_entry = {
                        "timestamp": entry["timestamp"],
                        "message_id": entry["message_id"],
                        "url": url,
                    }
                    self.fluent_bit_urls_sender.emit(None, url_entry)

            # remove from the main entry
            del entry["extracted_urls"]

            # are we sending extracted headers to a separate log source?
            if self.fluent_bit_headers_sender:
                for index, header in enumerate(entry["headers"]):
                    header_entry = {
                        "timestamp": entry["timestamp"],
                        "message_id": entry["message_id"],
                        "header": header,
                        "header_index": index,
                    }
                    self.fluent_bit_headers_sender.emit(None, header_entry)

                # remove from the main entry
                del entry["headers"]

        self.fluent_bit_main_sender.emit(None, entry)
        return True

    def export_lookalike_telemetry(self, entry: dict, analysis) -> bool:
        """Record the email into the thread store and emit look-a-like domain telemetry to fluent-bit."""
        from saq.modules.email.conversation import (
            derive_thread_context,
            get_established_domains,
            get_thread_message_count,
            record_thread,
        )
        from saq.domain_similarity import compare_domains, domain_attributes

        context = derive_thread_context(analysis)
        if not context.thread_id or not context.message_id:
            logging.debug("no thread/message id for %s - skipping lookalike telemetry", entry.get("message_id"))
            return False

        # compute + emit telemetry against PRIOR messages (before recording this one)
        if self.config.lookalike_telemetry_enabled and self.fluent_bit_lookalike_sender:
            established = get_established_domains(context)

            # one representative record per established domain (a thread can hold several roles per domain)
            reference_by_domain = {}
            for thread_domain in established:
                reference_by_domain.setdefault(thread_domain.domain, thread_domain)

            senders_payload = []
            for sender_participant in context.senders:
                attributes = domain_attributes(sender_participant.domain)
                senders_payload.append({
                    "address": sender_participant.address,
                    "role": sender_participant.role,
                    "domain": attributes["domain"],
                    "punycode": attributes["punycode"],
                    "mixed_script": attributes["mixed_script"],
                })

            comparisons = []
            for sender_participant in context.senders:
                for reference in reference_by_domain.values():
                    result = compare_domains(sender_participant.domain, reference.domain)
                    comparisons.append({
                        "suspect_domain": result.suspect,
                        "suspect_role": sender_participant.role,
                        "reference_domain": result.reference,
                        "reference_address": reference.address,
                        "reference_role": reference.role,
                        "reference_first_seen": str(reference.firstseendate) if reference.firstseendate else None,
                        "is_identical": result.is_identical,
                        "skeleton_equal": result.skeleton_equal,
                        "damerau_levenshtein": result.damerau_levenshtein,
                        "jaro_winkler": result.jaro_winkler,
                        "techniques": result.techniques,
                        "is_similar": result.is_similar,
                    })

            record = {
                "timestamp": self._entry_timestamp(entry),
                "message_id": context.message_id,
                "thread_id": context.thread_id,
                "thread_method": context.thread_method,
                "thread_message_count": get_thread_message_count(context.thread_id),
                "normalized_subject": context.normalized_subject,
                "senders": senders_payload,
                "established_domains": [{
                    "domain": d.domain,
                    "address": d.address,
                    "role": d.role,
                    "first_seen": str(d.firstseendate) if d.firstseendate else None,
                } for d in established],
                "comparisons": comparisons,
                # summary fields for cheap hunting without unpacking the comparisons array
                "comparison_count": len(comparisons),
                "any_similar": any(c["is_similar"] for c in comparisons),
                "any_mixed_script": any(s["mixed_script"] for s in senders_payload),
                "max_jaro_winkler": max((c["jaro_winkler"] for c in comparisons), default=0.0),
                "min_damerau_levenshtein": min((c["damerau_levenshtein"] for c in comparisons), default=None),
            }

            self.fluent_bit_lookalike_sender.emit(None, record)

        # record this message so later messages in the thread can compare against it
        if self.config.thread_recording_enabled:
            record_thread(context)

        return True

    @staticmethod
    def _entry_timestamp(entry: dict) -> Optional[str]:
        """Return the unix timestamp string for a log entry, matching the other exporters' date handling."""
        if entry.get("timestamp"):
            return entry["timestamp"]

        try:
            return str(datetime.strptime(entry["date"], '%Y-%m-%d %H:%M:%S.%f %z').timestamp())
        except (KeyError, TypeError, ValueError):
            return None

    def export_to_brocess(self, entry):
        """Exports the logging information to the brocess database."""

        mail_from = normalize_email_address(entry['mail_from'])
        if not mail_from:
            return

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
                    params = (
                        mail_from.encode("utf-8", errors="replace")[:255],
                        email_address.encode("utf-8", errors="replace")[:255],
                    )
                    execute_with_retry(db, c, sql, params)

                db.commit()

        except Exception as e:
            logging.error("unable to update brocess: {}".format(e))
            report_exception()
