import logging
import os
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
from saq.storage.s3 import get_s3_client
from saq.util.filesystem import delete_file
from saq.util.time import local_time

from datetime import datetime
import yara

class JournalEmailCollectorConfig(CollectorServiceConfiguration):
    blacklist_yara_rule_path: str = Field(..., description="the path to the yara rule for blacklisting emails")
    blacklist_yara_rule_check_frequency: int = Field(..., description="the frequency of checking the blacklist yara rule in seconds")
    delete_s3_objects: bool = Field(..., description="whether to delete s3 objects after collection")
    bucket_name: str = Field(default="journal-emails", description="the s3 bucket to poll for journal emails")

class JournalEmailCollectorService(CollectorService):
    """Service for collecting journal emails from an S3 bucket via polling."""

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

        self.client = get_s3_client()

        # inbound emails are scanned by this yara context to support node assignment
        self.blacklist_yara_rule_path: str = get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR).blacklist_yara_rule_path

        # check every N seconds to see if the blacklist yara rule has changed
        self.blacklist_yara_rule_check_frequency: int = get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR).blacklist_yara_rule_check_frequency
        self.blacklist_yara_rule_last_check: datetime = local_time()
        self.blacklist_yara_rule_last_mtime: int = 0

        self.yara_context: Optional[yara.Rules] = None

        self.bucket_name: str = get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR).bucket_name

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
                if get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR).delete_s3_objects:
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
            if get_service_config(SERVICE_JOURNAL_EMAIL_COLLECTOR).delete_s3_objects:
                try:
                    self.client.delete_object(Bucket=self.bucket_name, Key=object_key)
                    logging.info("deleted %s", object_key)
                except Exception as e:
                    logging.error("unable to delete %s: %s", object_key, e)
