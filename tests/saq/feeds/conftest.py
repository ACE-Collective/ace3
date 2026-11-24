"""Fixtures for the feed watch tests (docs/FEED_WATCHES.md)."""

import hashlib
import os
from typing import Optional

import pytest
import yaml
from sqlalchemy import func

from saq.configuration.config import get_config
from saq.configuration.schema import GitRepoConfig
from saq.database.model import Feed, FeedEntry, FeedWatch, FeedWatchFeed
from saq.database.pool import get_db
from saq.feeds import definitions as definitions_module
from saq.feeds.entries import identity_hash
from saq.feeds.service_config import FeedWatchServiceConfig, LLMEndpointConfig
from tests.saq.svs.yara.conftest import git

REPOSITORY = "unittest_feed_definitions"
LLM_URL = "http://llm.test"
LLM_MODEL = "gemma-4-e4b-it"
PROMPT = "You decide whether a security news entry answers the analyst's question."

EXPLOITED_RULE = """rule exploited
{
    strings:
        $a = "actively exploited" nocase
    condition:
        $a
}"""


class DefinitionsRepo:
    """A definitions checkout, as service_git keeps one at local_path."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(path)
        git(path, "init", "--quiet", "-b", "main")

    def write(self, relative: str, content: str) -> None:
        target = os.path.join(self.path, relative)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w") as fp:
            fp.write(content)

    def definition(self, name: str, yara: Optional[str] = None, question: Optional[str] = None, file: Optional[str] = None):
        document = {"name": name}
        if yara is not None:
            document["yara"] = yara
        if question is not None:
            document["question"] = question
        self.write(os.path.join("definitions", file or f"{name}.yaml"), yaml.safe_dump(document))

    def commit(self) -> str:
        git(self.path, "add", "-A")
        git(self.path, "commit", "--quiet", "--allow-empty", "-m", "change")
        return git(self.path, "rev-parse", "HEAD").strip()


def add_repository(tmp_path, monkeypatch, name: str = REPOSITORY, repositories: Optional[list[str]] = None) -> DefinitionsRepo:
    repo = DefinitionsRepo(str(tmp_path / name))
    get_config().add_git_repo_config(name, GitRepoConfig(
        name=name, description="unittest feed watch definitions", local_path=repo.path,
        git_url="https://example.invalid/definitions.git", update_frequency=60, branch="main"))
    monkeypatch.setattr(get_config().feeds, "repositories", repositories or [name])
    return repo


@pytest.fixture
def definitions_repo(tmp_path, monkeypatch) -> DefinitionsRepo:
    repo = add_repository(tmp_path, monkeypatch)
    repo.write(definitions_module.PROMPT_FILE, PROMPT)
    return repo


def service_config(**llm) -> FeedWatchServiceConfig:
    return FeedWatchServiceConfig(
        name="feed_watch", python_module="saq.feeds.service", python_class="FeedWatchService", description="unittest",
        enabled=True, workload_type="feed_watch", delete_files=True,
        llm=LLMEndpointConfig(**{"base_url": LLM_URL, "model": LLM_MODEL, "max_attempts": 2, **llm}))


def make_feed(name: str = "advisories", url: str = "https://vendor.example/feed.xml", baselined: bool = True, **fields) -> Feed:
    db = get_db()
    feed = Feed(name=name, url=url, poll_interval_seconds=900, created_at=func.now(),
                baselined_at=func.now() if baselined else None, **fields)
    db.add(feed)
    db.commit()
    return feed


def make_watch(feed: Feed, definition_name: str, name: Optional[str] = None, queue: str = "default",
               mode: str = "delivering", enabled: bool = True) -> FeedWatch:
    db = get_db()
    watch = FeedWatch(name=name or definition_name, definition_name=definition_name, queue=queue, mode=mode,
                      enabled=enabled, version=1, created_at=func.now(), updated_at=func.now())
    db.add(watch)
    db.flush()
    db.add(FeedWatchFeed(watch_id=watch.id, feed_id=feed.id))
    db.commit()
    return watch


def make_entry(feed: Feed, identity: str = "advisory-1", title: str = "Advisory 1", content: str = "",
               content_hash: Optional[str] = None, evaluated: bool = False, **fields) -> FeedEntry:
    db = get_db()
    entry = FeedEntry(feed_id=feed.id, identity=identity, identity_hash=identity_hash(identity),
                      content_hash=content_hash or hashlib.sha256(f"{title}\n{content}".encode()).hexdigest(),
                      title=title, link=f"https://vendor.example/{identity}",
                      content=content, first_seen_at=func.now(), last_seen_at=func.now(),
                      evaluated_at=func.now() if evaluated else None, **fields)
    db.add(entry)
    db.commit()
    return entry


def fresh(model, row_id):
    """The row as the database has it now, not as this session last saw it."""
    db = get_db()
    db.expire_all()
    return db.get(model, row_id)
