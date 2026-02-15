import logging
import os
import shutil
from typing import Generator, Optional, Type
from uuid import uuid4

from pydantic import Field

from saq.analysis.root import RootAnalysis, Submission
from saq.collectors.base_collector import Collector, CollectorService
from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.configuration.config import get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import ANALYSIS_MODE_EMAIL, ANALYSIS_TYPE_MAILBOX, DIRECTIVE_ARCHIVE, DIRECTIVE_NO_SCAN, DIRECTIVE_ORIGINAL_EMAIL, SERVICE_JOURNAL_EMAIL_COLLECTOR
from saq.environment import get_temp_dir
from saq.util.filesystem import delete_file
from saq.util.time import local_time

from datetime import datetime
import yara

class JournalEmailCollectorConfig(CollectorServiceConfiguration):
    blacklist_yara_rule_path: str = Field(..., description="the path to the yara rule for blacklisting emails")
    blacklist_yara_rule_check_frequency: int = Field(..., description="the frequency of checking the blacklist yara rule in seconds")
    source: str = Field(default="local", description="source type: local or s3")
    source_directory: str = Field(default="data/journal-emails", description="local directory to poll for journal emails")
    delete_files: bool = Field(default=True, description="whether to delete source files after collection")
    # s3-specific settings (only used when source is s3)
    delete_s3_objects: bool = Field(default=False, description="whether to delete s3 objects after collection")
    bucket_name: str = Field(default="journal-emails", description="the s3 bucket to poll for journal emails")

class JournalEmailCollectorService(CollectorService):
    """Service for collecting journal emails via polling."""

    def __init__(self, *args, **kwargs):
        super().__init__(collector=JournalEmailCollector(), config=get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR), *args, **kwargs)

    def start_single_threaded(self, *args, **kwargs):
        raise RuntimeError("JournalEmailCollectorService does not support single threaded execution")

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return JournalEmailCollectorConfig


class JournalEmailCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.service_config = get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR)
        self.source = self.service_config.source

        if self.source == "s3":
            from saq.storage.s3 import get_s3_client
            self.client = get_s3_client()
            self.bucket_name: str = self.service_config.bucket_name
        else:
            self.source_directory: str = self.service_config.source_directory
            # resolve relative paths against SAQ_HOME
            if not os.path.isabs(self.source_directory):
                saq_home = os.environ.get("SAQ_HOME", "")
                if saq_home:
                    self.source_directory = os.path.join(saq_home, self.source_directory)

        # inbound emails are scanned by this yara context to support node assignment
        self.blacklist_yara_rule_path: str = self.service_config.blacklist_yara_rule_path

        # check every N seconds to see if the blacklist yara rule has changed
        self.blacklist_yara_rule_check_frequency: int = self.service_config.blacklist_yara_rule_check_frequency
        self.blacklist_yara_rule_last_check: datetime = local_time()
        self.blacklist_yara_rule_last_mtime: int = 0

        self.yara_context: Optional[yara.Rules] = None

    #
    # processing
    #

    def should_load_blacklist_yara_rule(self) -> bool:
        """Returns True if the blacklist yara rule should be loaded, False otherwise."""
        if not self.blacklist_yara_rule_path:
            return False

        if not os.path.exists(self.blacklist_yara_rule_path):
            logging.warning("blacklist yara rule file %s does not exist", self.blacklist_yara_rule_path)
            return False

        if self.yara_context is not None:
            if (local_time() - self.blacklist_yara_rule_last_check).total_seconds() < self.blacklist_yara_rule_check_frequency:
                return False

        # has the file changed?
        return self.blacklist_yara_rule_last_mtime != os.path.getmtime(self.blacklist_yara_rule_path)

    def load_blacklist_yara_rule(self):
        """Loads the blacklist yara rule from the file."""
        self.yara_context = yara.compile(filepath=self.blacklist_yara_rule_path)

    def is_blacklisted(self, email_path: str) -> bool:
        """Returns True if the email is blacklisted, False otherwise."""
        if self.should_load_blacklist_yara_rule():
            self.load_blacklist_yara_rule()

        if self.yara_context is None:
            return False

        yara_matches = self.yara_context.match(email_path)

        # check for blacklisting first
        for match in yara_matches:
            for tag in match.tags:
                if tag == 'blacklist':
                    logging.info("%s matched blacklist rule %s", email_path, match.rule)
                    return True

        return False

    def collect(self) -> Generator[Submission, None, None]:
        if self.source == "s3":
            yield from self._collect_from_s3()
        else:
            yield from self._collect_from_local()

    def _collect_from_local(self) -> Generator[Submission, None, None]:
        """Collect journal emails from a local directory."""
        if not os.path.isdir(self.source_directory):
            logging.debug("source directory %s does not exist", self.source_directory)
            return

        try:
            files = [f for f in os.listdir(self.source_directory)
                     if os.path.isfile(os.path.join(self.source_directory, f))]
        except Exception as e:
            logging.error("failed to list files in %s: %s", self.source_directory, e)
            return

        if not files:
            return

        delete_files = self.service_config.delete_files

        for file_name in files:
            source_path = os.path.join(self.source_directory, file_name)

            # copy the email to a temp file
            email_path = os.path.join(get_temp_dir(), str(uuid4()))
            logging.info("copying email %s to %s", file_name, email_path)

            try:
                shutil.copy2(source_path, email_path)
            except Exception as e:
                logging.error("failed to copy %s to %s: %s", source_path, email_path, e)
                continue

            if self.is_blacklisted(email_path):
                delete_file(email_path)
                if delete_files:
                    try:
                        os.remove(source_path)
                        logging.info("deleted blacklisted file %s", file_name)
                    except Exception as e:
                        logging.error("unable to delete %s: %s", source_path, e)
                continue

            root_uuid = str(uuid4())
            storage_dir = os.path.join(get_temp_dir(), root_uuid)

            root = RootAnalysis(
                uuid=root_uuid,
                storage_dir=storage_dir,
                desc="ACE Mailbox Scanner Detection",
                analysis_mode=ANALYSIS_MODE_EMAIL,
                tool='ACE - Mailbox Scanner',
                tool_instance=self.fqdn,
                alert_type=ANALYSIS_TYPE_MAILBOX,
                event_time=local_time(),
                details={},
            )
            root.initialize_storage()
            email_observable = root.add_file_observable(email_path, target_path="email.rfc822", move=True)
            if email_observable:
                email_observable.add_directive(DIRECTIVE_NO_SCAN)
                email_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
                email_observable.add_directive(DIRECTIVE_ARCHIVE)

            yield Submission(root, key=file_name)

            logging.info("collected %s", file_name)
            if delete_files:
                try:
                    os.remove(source_path)
                    logging.info("deleted %s", file_name)
                except Exception as e:
                    logging.error("unable to delete %s: %s", source_path, e)

    def _collect_from_s3(self) -> Generator[Submission, None, None]:
        """Collect journal emails from an S3 bucket."""
        # list all objects in the journal emails bucket
        try:
            response = self.client.list_objects_v2(Bucket=self.bucket_name)
            objects = response.get("Contents", [])
        except Exception as e:
            logging.error("failed to list objects in bucket %s: %s", self.bucket_name, e)
            return

        if not objects:
            return

        for obj in objects:
            object_key = obj["Key"]

            # download the email to a temp file
            email_path = os.path.join(get_temp_dir(), str(uuid4()))
            logging.info("downloading email %s to %s", object_key, email_path)

            try:
                self.client.download_file(self.bucket_name, object_key, email_path)
            except Exception as e:
                logging.error("failed to download %s from %s: %s", object_key, self.bucket_name, e)
                continue

            if self.is_blacklisted(email_path):
                delete_file(email_path)
                # still delete from s3 if configured
                if self.service_config.delete_s3_objects:
                    try:
                        self.client.delete_object(Bucket=self.bucket_name, Key=object_key)
                        logging.info("deleted blacklisted object %s", object_key)
                    except Exception as e:
                        logging.error("unable to delete %s: %s", object_key, e)
                continue

            root_uuid = str(uuid4())
            storage_dir = os.path.join(get_temp_dir(), root_uuid)

            root = RootAnalysis(
                uuid=root_uuid,
                storage_dir=storage_dir,
                desc="ACE Mailbox Scanner Detection",
                analysis_mode=ANALYSIS_MODE_EMAIL,
                tool='ACE - Mailbox Scanner',
                tool_instance=self.fqdn,
                alert_type=ANALYSIS_TYPE_MAILBOX,
                event_time=local_time(),
                details={},
            )
            root.initialize_storage()
            email_observable = root.add_file_observable(email_path, target_path="email.rfc822", move=True)
            if email_observable:
                email_observable.add_directive(DIRECTIVE_NO_SCAN)
                email_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
                email_observable.add_directive(DIRECTIVE_ARCHIVE)

            yield Submission(root, key=object_key)

            logging.info("collected %s", object_key)
            if self.service_config.delete_s3_objects:
                try:
                    self.client.delete_object(Bucket=self.bucket_name, Key=object_key)
                    logging.info("deleted %s", object_key)
                except Exception as e:
                    logging.error("unable to delete %s: %s", object_key, e)
