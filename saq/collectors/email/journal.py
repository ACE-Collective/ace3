from dataclasses import dataclass
from datetime import datetime
import json
import logging
import os
from queue import Empty, Queue
import threading
import time
from typing import Generator, Optional
from uuid import uuid4

from saq.analysis.root import RootAnalysis, Submission
from saq.collectors.base_collector import Collector, CollectorService
from saq.collectors.collector_configuration import CollectorServiceConfiguration
from saq.configuration.config import get_config, get_config_value, get_config_value_as_boolean, get_config_value_as_int
from saq.constants import ANALYSIS_MODE_EMAIL, ANALYSIS_TYPE_MAILBOX, CONFIG_JOURNAL_EMAIL_COLLECTOR, CONFIG_JOURNAL_EMAIL_COLLECTOR_BLACKLIST_YARA_RULE_CHECK_FREQUENCY, CONFIG_JOURNAL_EMAIL_COLLECTOR_BLACKLIST_YARA_RULE_PATH, CONFIG_JOURNAL_EMAIL_COLLECTOR_DELETE_S3_OBJECTS, CONFIG_RABBITMQ, CONFIG_RABBITMQ_HOST, CONFIG_RABBITMQ_PASSWORD, CONFIG_RABBITMQ_PORT, CONFIG_RABBITMQ_USER, DIRECTIVE_ARCHIVE, DIRECTIVE_NO_SCAN, DIRECTIVE_ORIGINAL_EMAIL, G_TEMP_DIR
from saq.environment import g
from saq.error.reporting import report_exception
from saq.storage.minio import get_minio_client
from saq.util.filesystem import delete_file
from saq.util.time import local_time

from minio import Minio
import pika
import yara

@dataclass
class JournalEmailMessageLocation:
    """Location of a journal email message in s3 storage."""
    bucket_name: str
    object_key: str
    object_size: int
    event_time: str

class JournalEmailCollectorService(CollectorService):
    """Service for collecting journal emails from an S3 bucket."""

    def __init__(self, *args, **kwargs):
        super().__init__(collector=JournalEmailCollector(), config=CollectorServiceConfiguration.from_config(get_config()[CONFIG_JOURNAL_EMAIL_COLLECTOR]), *args, **kwargs)

        # extra thread dedicated to consuming messages from the journal queue
        self.consumer_thread: threading.Thread

    def start_single_threaded(self, *args, **kwargs):
        raise RuntimeError("JournalEmailCollectorService does not support single threaded execution")

    def start_multi_threaded(self, *args, **kwargs):
        super().start_multi_threaded(*args, **kwargs)
        assert isinstance(self.collector, JournalEmailCollector)

        self.consumer_thread = threading.Thread(target=self.collector.consumer_loop, name="Journal Email Collector Consumer")
        self.consumer_thread.start()

    def stop(self):
        assert isinstance(self.collector, JournalEmailCollector)
        super().stop()
        self.collector.stop_consumer_loop()

    def wait(self):
        logging.info("waiting for consumer thread to terminate")
        self.consumer_thread.join()
        super().wait()


class JournalEmailCollector(Collector):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # JournalEmailMessageLocation messages are pulled from ampq and pushed into this queue
        self.message_queue: Queue[JournalEmailMessageLocation] = Queue()

        self.connection: pika.BlockingConnection
        self.channel: pika.Channel
        self.queue_name: str
        self.consumer_tag: str
        self.consumer_loop_shutdown: bool = False

        self.client: Minio = get_minio_client()

        # inbound emails are scanned by this yara context to support node assignment
        self.blacklist_yara_rule_path: str = get_config_value(CONFIG_JOURNAL_EMAIL_COLLECTOR, CONFIG_JOURNAL_EMAIL_COLLECTOR_BLACKLIST_YARA_RULE_PATH)

        # check every N seconds to see if the blacklist yara rule has changed
        self.blacklist_yara_rule_check_frequency: int = get_config_value_as_int(CONFIG_JOURNAL_EMAIL_COLLECTOR, CONFIG_JOURNAL_EMAIL_COLLECTOR_BLACKLIST_YARA_RULE_CHECK_FREQUENCY)
        self.blacklist_yara_rule_last_check: datetime = local_time()
        self.blacklist_yara_rule_last_mtime: int = 0

        self.yara_context: Optional[yara.Rules] = None

    #
    # ampq 
    #

    def connect(self) -> bool:
        credentials = pika.PlainCredentials(
            get_config_value(CONFIG_RABBITMQ, CONFIG_RABBITMQ_USER), 
            get_config_value(CONFIG_RABBITMQ, CONFIG_RABBITMQ_PASSWORD))

        parameters = pika.ConnectionParameters(
            host=get_config_value(CONFIG_RABBITMQ, CONFIG_RABBITMQ_HOST),
            port=get_config_value(CONFIG_RABBITMQ, CONFIG_RABBITMQ_PORT),
            credentials=credentials)

        self.connection = pika.BlockingConnection(parameters)
        self.channel = self.connection.channel()

        self.channel.exchange_declare(
            exchange="minio-events",
            exchange_type="topic",
            durable=True
        )

        queue_result = self.channel.queue_declare(queue="journal")
        self.queue_name = queue_result.method.queue

        self.channel.queue_bind(
            exchange="minio-events",
            queue=self.queue_name,
            routing_key="minio.object.*"
        )

        logging.info(f"connected to {parameters.host}:{parameters.port} queue {self.queue_name}")
        return True

    def handle_object_created(self, bucket_name: str, object_key: str, object_size: int, event_time: str):
        logging.info(f"handling object created: {bucket_name}/{object_key}")
        logging.info(f"object size: {object_size} bytes, event time: {event_time}")
        self.message_queue.put(JournalEmailMessageLocation(bucket_name, object_key, object_size, event_time))
    
    def process_message(self, body: bytes) -> bool:
        notification: dict = json.loads(body.decode("utf-8"))

        # Extract relevant information
        event_type = notification.get("EventName", "unknown")
        bucket_name = notification.get("Records", [{}])[0].get("s3", {}).get("bucket", {}).get("name", "unknown")
        object_key = notification.get("Records", [{}])[0].get("s3", {}).get("object", {}).get("key", "unknown")
        object_size = notification.get("Records", [{}])[0].get("s3", {}).get("object", {}).get("size", 0)
        event_time = notification.get("Records", [{}])[0].get("eventTime", "unknown")
        
        logging.info(f"received notification: {event_type} for {bucket_name}/{object_key}")
        logging.info(f"object size: {object_size} bytes, event time: {event_time}")
        
        # Process based on event type
        if event_type == "s3:ObjectCreated:Put":
            self.handle_object_created(bucket_name, object_key, object_size, event_time)
        else:
            logging.info(f"unhandled event type: {event_type}")

        return True

    def consumer_loop(self):
        while True:
            try:
                self.connect()

                def _callback(channel, method, properties, body):
                    logging.info(f"received message on {method.routing_key}")
                    if self.process_message(body):
                        logging.info(f"acknowledging message on {method.routing_key}")
                        channel.basic_ack(delivery_tag=method.delivery_tag)

                self.consumer_tag = self.channel.basic_consume(
                    queue=self.queue_name,
                    on_message_callback=_callback,
                    auto_ack=False
                )

                logging.info(f"consumer tag: {self.consumer_tag}")

                # NOTE this blocks
                logging.info(f"waiting for messages on queue {self.queue_name}")
                self.channel.start_consuming()
                logging.info(f"stopped consuming messages on queue {self.queue_name}")

            except Exception as e:
                logging.error(f"unable to connect to rabbitmq: {e}")
                report_exception()
                if not self.consumer_loop_shutdown:
                    time.sleep(1)

            if self.consumer_loop_shutdown:
                break

    def stop_consumer_loop(self):
        logging.info(f"stopping consumer loop on queue {self.consumer_tag}")
        self.consumer_loop_shutdown = True
        self.channel.connection.add_callback_threadsafe(lambda: self.channel.basic_cancel(self.consumer_tag))

    #
    # processing
    #

    def should_load_blacklist_yara_rule(self) -> bool:
        """Returns True if the blacklist yara rule should be loaded, False otherwise."""
        if not self.blacklist_yara_rule_path:
            return False

        if not os.path.exists(self.blacklist_yara_rule_path):
            logging.warning(f"blacklist yara rule file {self.blacklist_yara_rule_path} does not exist")
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
                    logging.info(f"{email_path} matched blacklist rule {match.rule}")
                    return True

        return False

    def collect(self) -> Generator[Submission, None, None]:
        while True:
            try:
                journal_email_message_location: JournalEmailMessageLocation = self.message_queue.get(timeout=1)
            except Empty:
                return

            logging.info(f"got {journal_email_message_location}")

            # temp directory for the email and the submission
            email_path = os.path.join(g(G_TEMP_DIR), str(uuid4()))
            logging.info(f"downloading email {journal_email_message_location.object_key} to {email_path}")
            self.client.fget_object(journal_email_message_location.bucket_name, journal_email_message_location.object_key, email_path)

            if self.is_blacklisted(email_path):
                delete_file(email_path)
                continue

            root_uuid = str(uuid4())
            storage_dir = os.path.join(g(G_TEMP_DIR), root_uuid)

            root = RootAnalysis(
                uuid = root_uuid,
                storage_dir = storage_dir,
                desc = "ACE Mailbox Scanner Detection",
                analysis_mode = ANALYSIS_MODE_EMAIL,
                tool = 'ACE - Mailbox Scanner',
                tool_instance = self.fqdn,
                alert_type = ANALYSIS_TYPE_MAILBOX,
                event_time = local_time(),
                #event_time = datetime.fromtimestamp(os.path.getmtime(email_path)),
                details = {},
            )
            root.initialize_storage()
            email_observable = root.add_file_observable(email_path, target_path="email.rfc822", move=True)
            if email_observable:
                email_observable.add_directive(DIRECTIVE_NO_SCAN)
                email_observable.add_directive(DIRECTIVE_ORIGINAL_EMAIL)
                email_observable.add_directive(DIRECTIVE_ARCHIVE)

            yield Submission(root, key=journal_email_message_location.object_key)

            logging.info(f"collected {journal_email_message_location.object_key}")
            if get_config_value_as_boolean(CONFIG_JOURNAL_EMAIL_COLLECTOR, CONFIG_JOURNAL_EMAIL_COLLECTOR_DELETE_S3_OBJECTS):
                try:
                    self.client.remove_object(journal_email_message_location.bucket_name, journal_email_message_location.object_key)
                    logging.info(f"deleted {journal_email_message_location.object_key}")
                except Exception as e:
                    logging.error(f"unable to delete {journal_email_message_location.object_key}: {e}")
