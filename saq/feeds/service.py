"""service_feed_watch: polls RSS and Atom feeds and alerts on what watches match (docs/FEED_WATCHES.md).

Everything runs on the primary node only; elsewhere the service stays idle. Two threads:

- the feed loop, every loop_interval_seconds: reads the definitions again when a repository's commit
  moved (and copies them into feed_definitions), polls the feeds that are due, evaluates the new entry
  versions, stages the matches that are ready as alerts, starts queued replays and, hourly, deletes
  what expired;
- the classifier, which asks the pending questions of the LLM endpoint, so a slow endpoint never holds
  up polling.

The alerts are staged into this service's own collector (saq.collectors), which hands them to the
engine and checks their submission keys with the DuplicateSubmissionFilter.
"""

import logging
import threading
import time
from typing import Generator, Optional, Type, override

import yara

from saq.analysis.root import Submission
from saq.collectors.base_collector import Collector, CollectorExecutionMode, CollectorService
from saq.collectors.submission_file_manager import SubmissionFileManager
from saq.configuration.config import get_config, get_service_config
from saq.configuration.schema import ServiceConfig
from saq.constants import SERVICE_FEED_WATCH
from saq.database.pool import remove_all_sessions
from saq.database.util.node import is_primary_node
from saq.error.reporting import log_loop_exception
from saq.feeds import decisions, definitions, delivery, entries, poller, replay
from saq.feeds.matching import RuleError, compile_rule, scan_entry
from saq.feeds.service_config import FeedWatchServiceConfig
from saq.service import ACEServiceInterface

# how often expired entries, deliveries and replays are deleted
PRUNE_INTERVAL_SECONDS = 3600

# the most staged alerts one collection pass hands on
MAX_SUBMISSIONS_PER_COLLECTION = 32

# how often wait() checks for stop()
WAIT_POLL_SECONDS = 1

# what a stopping thread needs beyond its slowest request
STOP_MARGIN_SECONDS = 5

# how long evaluation waits for a definitions repository's checkout (longer than a first clone takes)
# before it says so at ERROR, and how often it says it again
HELD_REPORT_SECONDS = 3600


class FeedWatchCollector(Collector):
    """Hands the staged feed watch alerts to the collector service, which schedules them."""

    collect_until_empty = True

    def __init__(self, file_manager: Optional[SubmissionFileManager] = None):
        super().__init__()
        self.file_manager = file_manager

    @override
    def collect(self) -> Generator[Submission, None, None]:
        yield from self.file_manager.iter_staged_submissions(limit=MAX_SUBMISSIONS_PER_COLLECTION)


class Definitions:
    """The definitions and their compiled rules, read again when a repository's commit moves. The feed
    loop refreshes it; the classifier reads the current set."""

    def __init__(self):
        self._lock = threading.Lock()
        self._current = definitions.DefinitionSet()
        self.rules: dict = {}
        self.compile_errors: dict[str, str] = {}
        # every repository had a checkout when they were last read. Until then no entry is evaluated:
        # evaluated without its definitions, an entry would never be evaluated again
        self.complete = False
        self.read = False
        # time.monotonic() when the repositories were first read without a checkout of each
        self.incomplete_since: Optional[float] = None

    @property
    def current(self) -> definitions.DefinitionSet:
        with self._lock:
            return self._current

    def refresh(self, force: bool = False) -> bool:
        """Reads the repositories again if a commit moved. Returns whether it did."""
        commits = definitions.current_commits()
        if not force and self.read and commits == self.current.commits:
            return False

        loaded = definitions.read_definitions(commits)
        rules, errors = {}, {}
        for name, definition in loaded.definitions.items():
            if not definition.yara:
                continue
            try:
                rules[name] = compile_rule(definition.yara)
            except RuleError as e:
                errors[name] = f"the rule does not compile: {e}"
                logging.error("the rule of feed watch definition %s (%s/%s) does not compile: %s", name,
                              definition.repository, definition.path, e, exc_info=e,
                              extra={"definition": name, "repository": definition.repository, "path": definition.path})

        definitions.sync_definitions(loaded, errors)
        with self._lock:
            self._current = loaded
            self.rules = rules
            self.compile_errors = errors
        self.read = True
        self.complete = all(commit is not None for _, commit in commits)
        if self.complete:
            self.incomplete_since = None
        elif self.incomplete_since is None:
            self.incomplete_since = time.monotonic()
        logging.info("read %d feed watch definitions (%d unusable) at %s", len(loaded.definitions),
                     len(errors) + len(loaded.errors), commits)
        return True

    def matcher(self, model: str) -> decisions.Matcher:
        with self._lock:
            current, rules, errors = self._current, self.rules, self.compile_errors

        def scan(definition, fields):
            try:
                found = scan_entry(rules[definition.name], fields)
            except yara.Error as e:
                raise decisions.ScanError(str(e)) from e
            return found.matched, found.field, found.excerpt

        usable = {name for name in current.definitions if name not in errors}
        return decisions.Matcher(definitions=current, usable=usable, scan=scan, model=model)


class FeedWatchService(ACEServiceInterface):

    @classmethod
    def get_config_class(cls) -> Type[ServiceConfig]:
        return FeedWatchServiceConfig

    def __init__(self):
        self.config: FeedWatchServiceConfig = get_service_config(SERVICE_FEED_WATCH)
        self.shutdown = threading.Event()
        self.collector = FeedWatchCollector()
        self.collector_service = CollectorService(self.collector, config=self.config)
        self.collector.file_manager = self.collector_service.file_manager
        self.definitions = Definitions()
        self.classifier_state = decisions.ClassifierState()
        self.threads: list[threading.Thread] = []
        self.collector_started = False
        self.next_prune = 0.0
        self.next_held_report = 0.0

    def should_stop(self) -> bool:
        return self.shutdown.is_set()

    @property
    def model(self) -> str:
        return self.config.llm.model if self.config.llm is not None else ""

    def _step(self, name: str, function, *args):
        try:
            return function(*args)
        except Exception as e:
            log_loop_exception(e, f"feed watch {name} failed")
            return None
        finally:
            remove_all_sessions()

    def poll_due_feeds(self) -> int:
        polled = 0
        for feed_id in poller.due_feeds():
            if self.should_stop():
                break
            try:
                poller.poll_feed(feed_id, self.config)
            finally:
                remove_all_sessions()
            polled += 1
        return polled

    def report_held_evaluation(self) -> None:
        """No entry is evaluated, so no watch alerts, while a repository has no checkout. read_definitions
        logs it when it reads them; a checkout that never comes is said at ERROR again, hourly."""
        now = time.monotonic()
        since = self.definitions.incomplete_since
        if since is None or now - since < HELD_REPORT_SECONDS or now < self.next_held_report:
            return
        self.next_held_report = now + HELD_REPORT_SECONDS
        missing = [repository for repository, commit in self.definitions.current.commits if commit is None]
        # an exception for the record, so ErrorReportHandler reports it
        error = definitions.DefinitionError(f"no checkout of {', '.join(missing)}")
        logging.error("no feed entry has been evaluated for %.0f minutes: feed watch definitions repositories %s "
                      "have no checkout", (now - since) / 60, ", ".join(missing), exc_info=error,
                      extra={"repositories": missing})

    def evaluate(self) -> int:
        if not self.definitions.complete:
            # the entries wait for the checkout: evaluated without their definitions, they never would be
            self.report_held_evaluation()
            return 0
        total = 0
        while not self.should_stop():
            count = decisions.evaluate_entries(self.definitions.matcher(self.model), self.should_stop)
            total += count
            if count < decisions.EVALUATE_BATCH:
                break
        return total

    def prune(self) -> None:
        if time.monotonic() < self.next_prune:
            return
        self.next_prune = time.monotonic() + PRUNE_INTERVAL_SECONDS
        removed = entries.prune_entries(self.should_stop)
        replays = replay.prune_replays()
        if removed or replays:
            logging.info("deleted %d expired feed entry versions and %d replays", removed, replays)

    def feed_pass(self) -> None:
        """One pass of the feed loop; each step fails on its own."""
        self._step("definition refresh", self.definitions.refresh)
        self._step("poll", self.poll_due_feeds)
        self._step("evaluation", self.evaluate)
        self._step("delivery", delivery.deliver, self.collector_service.file_manager, self.should_stop)
        self._step("replay", replay.run_replays, self.definitions.current, self.model, self.should_stop)
        self._step("prune", self.prune)

    def classify_pass(self) -> int:
        return self._step("classification", decisions.classify_pending, self.config, self.definitions.current,
                          self.classifier_state, self.should_stop) or 0

    def feed_loop(self):
        while not self.should_stop():
            self.feed_pass()
            self.shutdown.wait(self.config.loop_interval_seconds)

    def classify_loop(self):
        while not self.should_stop():
            # a full batch means more are waiting
            if self.classify_pass() < (self.config.llm.batch_size if self.config.llm else 1):
                self.shutdown.wait(self.config.loop_interval_seconds)

    @override
    def start(self):
        if not is_primary_node():
            logging.info("feed watches run on the primary node only; this service stays idle")
            return

        if not get_config().feeds.repositories:
            logging.warning("feeds.repositories is empty: feeds are polled, but no watch has a definition")

        self._step("replay recovery", replay.requeue_interrupted)

        self.collector_service.start()
        self.collector_started = True
        for name, target in (("feed-watch", self.feed_loop), ("feed-watch-classifier", self.classify_loop)):
            thread = threading.Thread(target=target, name=name, daemon=True)
            thread.start()
            self.threads.append(thread)

    @override
    def wait_for_start(self, timeout: float = 5) -> bool:
        if not self.collector_started:
            return True
        return self.collector_service.wait_for_start(timeout)

    @override
    def start_single_threaded(self):
        """One pass of the feed loop, the classifier and the collector, then returns (`ace service start
        --single-threaded feed_watch` exits)."""
        try:
            self.feed_pass()
            self.classify_pass()
            # what the classifier just matched
            self._step("delivery", delivery.deliver, self.collector_service.file_manager, self.should_stop)
            self.collector_service.start_single_threaded(execution_mode=CollectorExecutionMode.SINGLE_SHOT)
        finally:
            self.shutdown.set()

    @override
    def stop(self):
        self.shutdown.set()
        if self.collector_started:
            self.collector_service.stop()

    def join_timeout(self) -> float:
        """The longest one step of a thread can take to notice the stop: its slowest request."""
        longest = max(self.config.fetch_deadline_seconds,
                      self.config.fetch_connect_timeout_seconds + self.config.fetch_read_timeout_seconds)
        if self.config.llm is not None:
            longest = max(longest, self.config.llm.connect_timeout_seconds + self.config.llm.read_timeout_seconds)
        return longest + STOP_MARGIN_SECONDS

    @override
    def wait(self):
        # runs until stopped, idle or not: `ace service start` reads a wait() that returns as the
        # service having finished, and bounds this wait once it stops us. stop() already waited for
        # the collector
        while not self.shutdown.wait(WAIT_POLL_SECONDS):
            continue
        for thread in self.threads:
            thread.join(self.join_timeout())
            if thread.is_alive():
                logging.warning("feed watch thread %s did not stop within %.0fs", thread.name, self.join_timeout())
