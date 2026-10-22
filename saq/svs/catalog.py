"""The Atomic Red Team test catalog (docs/SVS_RUNS.md, *The Atomic Red Team catalog*).

ACE never runs a test. It holds ART repositories only as a catalog: to validate a run's test GUID,
to show a test's name, description and commands, to check its supported platforms, and to know its
ATT&CK technique [ART-12].

Each repository in svs.catalog.repositories is the name of an ordinary `git_repo_*` section. service_git
keeps its checkout at local_path up to date, and service_svs reads `atomics/T*/T*.yaml` from that
checkout into svs_catalog_tests whenever its commit changes (refresh_catalog). A test without an
`auto_generated_guid` is skipped with a warning, and a GUID already taken by another test (in this
repository or another) is skipped too: the first one read keeps it. A test that disappears keeps
its row, with removed_at set, so its runs keep their test. So does every test of a repository taken
out of svs.catalog.repositories: nothing reads it any more, so its tests can't stay in the catalog.

A refresh locks its repository's row while it writes, so two nodes never interleave. When the
checkout's commit moves while the files are read (service_git pulled), nothing is stored and the
next refresh reads the new commit.
"""

import glob
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

import yaml
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from saq.configuration.config import get_config
from saq.database.model import SVSCatalogRepository, SVSCatalogTest
from saq.database.pool import get_db
from saq.git import get_commit_hash
from saq.svs.attack import normalize_platform
from saq.util import abs_path
from saq.util.url import strip_url_credentials

ATOMICS_GLOB = os.path.join("atomics", "T*", "T*.yaml")

# a larger atomic file is not one; ART's biggest is a few hundred KB
MAX_ATOMIC_FILE_BYTES = 10 * 1024 * 1024


class CatalogError(RuntimeError):
    """The repository can't be read; the message is stored on its row."""


@dataclass(frozen=True)
class CatalogEntry:
    """One test as its atomic file defines it."""

    guid: str
    technique: str
    technique_name: Optional[str]
    name: str
    description: Optional[str]
    platforms: tuple[str, ...]
    executor: Optional[str]
    # the test's own entry in the atomic file
    test: dict
    # where it came from, relative to the checkout
    path: str

    @property
    def content_hash(self) -> str:
        return content_hash(self.test)


def content_hash(test: dict) -> str:
    """sha256 of the test's entry, canonically serialized: it changes exactly when the test does."""
    return hashlib.sha256(json.dumps(test, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


@dataclass
class ParseResult:
    entries: list[CatalogEntry] = field(default_factory=list)
    # (path, test name or None, reason) of everything not read
    skipped: list[tuple[str, Optional[str], str]] = field(default_factory=list)


def _text(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value).strip() or None


def parse_atomic_file(root: str, path: str, result: ParseResult) -> None:
    """Adds the tests of one atomic file to result."""
    relative = os.path.relpath(path, root)
    try:
        if os.path.getsize(path) > MAX_ATOMIC_FILE_BYTES:
            result.skipped.append((relative, None, f"larger than {MAX_ATOMIC_FILE_BYTES} bytes"))
            return

        with open(path, "rb") as fp:
            document = yaml.safe_load(fp)
    except (OSError, yaml.YAMLError) as e:
        result.skipped.append((relative, None, f"unreadable: {e}"))
        return

    if not isinstance(document, dict) or not isinstance(document.get("atomic_tests"), list):
        result.skipped.append((relative, None, "not an atomic file (no atomic_tests list)"))
        return

    technique = _text(document.get("attack_technique")) or os.path.basename(os.path.dirname(path))
    technique_name = _text(document.get("display_name"))

    for index, test in enumerate(document["atomic_tests"]):
        if not isinstance(test, dict):
            result.skipped.append((relative, None, f"atomic test {index} is not a mapping"))
            continue

        name = _text(test.get("name")) or f"atomic test {index}"
        guid = _text(test.get("auto_generated_guid"))
        if guid is None:
            result.skipped.append((relative, name, "no auto_generated_guid"))
            continue

        platforms = test.get("supported_platforms") or []
        if not isinstance(platforms, list):
            platforms = [platforms]
        executor = test.get("executor") if isinstance(test.get("executor"), dict) else {}

        result.entries.append(CatalogEntry(
            guid=guid.lower(),
            technique=technique.upper(),
            technique_name=technique_name,
            name=name[:512],
            description=_text(test.get("description")),
            platforms=tuple(str(platform).strip().lower() for platform in platforms if str(platform).strip()),
            executor=_text(executor.get("name")),
            test=test,
            path=relative,
        ))


def parse_atomics(root: str) -> ParseResult:
    """Every test in atomics/T*/T*.yaml under root, in file order. A GUID seen twice keeps its
    first test; the others are skipped."""
    result = ParseResult()
    for path in sorted(glob.glob(os.path.join(root, ATOMICS_GLOB))):
        parse_atomic_file(root, path, result)

    seen: set[str] = set()
    unique = []
    for entry in result.entries:
        if entry.guid in seen:
            result.skipped.append((entry.path, entry.name, f"auto_generated_guid {entry.guid} is used by an earlier test"))
            continue
        seen.add(entry.guid)
        unique.append(entry)

    result.entries = unique
    return result


#
# storing
#

@dataclass
class RefreshResult:
    repository: str
    commit: Optional[str] = None
    # false when the commit was already read, or the refresh failed
    refreshed: bool = False
    tests: int = 0
    added: int = 0
    changed: int = 0
    removed: int = 0
    skipped: list[tuple[str, Optional[str], str]] = field(default_factory=list)
    error: Optional[str] = None
    # the repository is no longer in svs.catalog.repositories and its tests were removed
    retired: bool = False


def _checkout(repository: str) -> str:
    if repository not in get_config().svs.catalog.repositories:
        raise CatalogError(f"{repository} is not in svs.catalog.repositories")
    try:
        repo_config = get_config().get_git_repo_config(repository)
    except ValueError:
        raise CatalogError(f"svs.catalog.repositories names {repository}, but no git_repo section is named {repository}") from None

    path = abs_path(repo_config.local_path)
    if not os.path.isdir(path):
        raise CatalogError(f"the checkout of {repository} ({path}) does not exist yet; is service_git running?")
    return path


def _lock_repository(repository: str) -> SVSCatalogRepository:
    """The repository's row, locked until the transaction ends (created on first use)."""
    db = get_db()
    row = db.query(SVSCatalogRepository).filter(SVSCatalogRepository.name == repository).with_for_update().one_or_none()
    if row is not None:
        return row

    try:
        db.add(SVSCatalogRepository(name=repository))
        db.commit()
    except IntegrityError:
        # another node created it first
        db.rollback()

    return db.query(SVSCatalogRepository).filter(SVSCatalogRepository.name == repository).with_for_update().one()


def _record_error(repository: str, error: str) -> None:
    db = get_db()
    try:
        row = _lock_repository(repository)
        row.error = error
        db.commit()
    except Exception:
        db.rollback()
        raise


def _apply(row: SVSCatalogTest, entry: CatalogEntry, repository: str, commit: str) -> bool:
    """Sets the row from the entry. Returns whether anything changed; the commit moves only with
    the test, so a new commit of the repository doesn't touch tests it didn't change."""
    values = {
        "repository": repository,
        "technique": entry.technique,
        "technique_name": entry.technique_name,
        "name": entry.name,
        "description": entry.description,
        "platforms": json.dumps(list(entry.platforms)),
        "executor": entry.executor,
        "test": json.dumps(entry.test, sort_keys=True, default=str),
        "content_hash": entry.content_hash,
        "path": entry.path,
        "removed_at": None,
    }
    changed = any(getattr(row, key) != value for key, value in values.items())
    if row.content_hash != entry.content_hash or row.commit is None:
        values["commit"] = commit
    for key, value in values.items():
        setattr(row, key, value)
    return changed


def _store(repository: str, commit: str, parsed: ParseResult, result: RefreshResult) -> None:
    db = get_db()
    now = datetime.now()
    try:
        row = _lock_repository(repository)
        guids = [entry.guid for entry in parsed.entries]
        existing = {test.guid: test for test in db.query(SVSCatalogTest).filter(
            or_(SVSCatalogTest.repository == repository, SVSCatalogTest.guid.in_(guids)))}

        stored = set()
        for entry in parsed.entries:
            test = existing.get(entry.guid)
            if test is not None and test.repository != repository and test.removed_at is None:
                result.skipped.append((entry.path, entry.name,
                                       f"auto_generated_guid {entry.guid} belongs to a test of {test.repository}"))
                continue

            if test is None:
                test = SVSCatalogTest(guid=entry.guid, first_seen_at=now)
                db.add(test)
                result.added += 1
                _apply(test, entry, repository, commit)
            elif _apply(test, entry, repository, commit):
                result.changed += 1
            stored.add(entry.guid)

        for guid, test in existing.items():
            if test.repository == repository and guid not in stored and test.removed_at is None:
                test.removed_at = now
                result.removed += 1

        row.commit = commit
        row.refreshed_at = now
        row.test_count = len(stored)
        row.skipped_count = len(result.skipped)
        row.error = None
        db.commit()
    except Exception:
        db.rollback()
        raise

    result.tests = len(stored)
    result.refreshed = True


def refresh_repository(repository: str, *, force: bool = False) -> RefreshResult:
    """Reads the repository's tests into the catalog if its checkout's commit changed since the
    last refresh (or force). A failure is recorded on the repository's row and returned in error."""
    result = RefreshResult(repository=repository)
    extra = {"repository": repository}
    try:
        path = _checkout(repository)
        commit = get_commit_hash(path)
        if commit is None:
            raise CatalogError(f"the checkout of {repository} ({path}) is not a git repository")
        result.commit = extra["commit"] = commit

        current = get_db().query(SVSCatalogRepository).filter(SVSCatalogRepository.name == repository).one_or_none()
        if not force and current is not None and current.commit == commit and current.error is None:
            return result

        parsed = parse_atomics(path)
        if get_commit_hash(path) != commit:
            # service_git pulled while the files were read: they may be a mix of two commits
            logging.info("svs catalog %s moved while it was read; the next refresh reads the new commit",
                         repository, extra=extra)
            return result

        result.skipped = list(parsed.skipped)
        _store(repository, commit, parsed, result)
    except Exception as e:
        result.error = str(e) if isinstance(e, CatalogError) else f"refresh failed: {e}"
        logging.error("svs catalog refresh of %s failed: %s", repository, result.error, extra=extra,
                      exc_info=not isinstance(e, CatalogError))
        try:
            _record_error(repository, result.error)
        except Exception as record_failure:
            logging.error("unable to record the svs catalog error of %s: %s", repository, record_failure, extra=extra)
        return result

    for path, name, reason in result.skipped:
        logging.warning("svs catalog skipped a test of %s: %s", repository, reason,
                        extra={**extra, "path": path, "test_name": name, "reason": reason})
    logging.info("svs catalog of %s refreshed", repository,
                 extra={**extra, "tests": result.tests, "added": result.added, "changed": result.changed,
                        "removed": result.removed, "skipped": len(result.skipped)})
    return result


RETIRED_ERROR = "no longer in svs.catalog.repositories; its tests were removed"


def retire_repository(repository: str) -> RefreshResult:
    """Removes the tests of a repository that is no longer in svs.catalog.repositories. They keep
    their rows and runs, as a test that disappears does. The error on its row makes the next refresh
    read it again if it is listed again, whatever its commit."""
    result = RefreshResult(repository=repository, retired=True)
    db = get_db()
    now = datetime.now()
    try:
        row = _lock_repository(repository)
        result.removed = db.query(SVSCatalogTest).filter(
            SVSCatalogTest.repository == repository,
            SVSCatalogTest.removed_at.is_(None)).update({SVSCatalogTest.removed_at: now}, synchronize_session=False)
        row.test_count = 0
        row.error = RETIRED_ERROR
        db.commit()
    except Exception:
        db.rollback()
        raise

    logging.warning("svs catalog repository %s is no longer in svs.catalog.repositories: %d tests removed",
                    repository, result.removed, extra={"repository": repository, "removed": result.removed})
    return result


def refresh_catalog(*, force: bool = False) -> list[RefreshResult]:
    """Refreshes every repository in svs.catalog.repositories, and retires every other repository
    that still has tests in the catalog."""
    configured = get_config().svs.catalog.repositories
    results = [refresh_repository(repository, force=force) for repository in configured]
    unconfigured = [repository for (repository,) in get_db().query(SVSCatalogTest.repository).filter(
        SVSCatalogTest.removed_at.is_(None), SVSCatalogTest.repository.notin_(configured)).distinct()]
    for repository in sorted(unconfigured):
        try:
            results.append(retire_repository(repository))
        except Exception as e:
            logging.error("unable to retire the svs catalog repository %s: %s", repository, e,
                          extra={"repository": repository}, exc_info=True)
            results.append(RefreshResult(repository=repository, retired=True, error=f"retire failed: {e}"))
    return results


@dataclass
class RepositoryStatus:
    """A catalog repository as `ace svs catalog status` and GET /api/v2/svs/catalog/repositories
    show it: every repository in svs.catalog.repositories, and every one that has a row."""

    name: str
    # it is in svs.catalog.repositories
    configured: bool
    # from its git_repo_* section, None without one; git_url never carries credentials
    git_url: Optional[str]
    branch: Optional[str]
    # the commit the catalog holds and when it was read, None until it is first read
    commit: Optional[str]
    refreshed_at: Optional[datetime]
    test_count: int
    skipped_count: int
    # tests of the repository removed from the catalog since they were first read
    removed_count: int
    # why the last refresh failed, None when it succeeded or the repository is retired
    error: Optional[str]
    # taken out of svs.catalog.repositories, so its tests were removed
    retired: bool


def repository_status() -> list[RepositoryStatus]:
    """Every catalog repository's status, by name."""
    configured = get_config().svs.catalog.repositories
    db = get_db()
    rows = {row.name: row for row in db.query(SVSCatalogRepository)}
    removed = dict(db.query(SVSCatalogTest.repository, func.count(SVSCatalogTest.id))
                   .filter(SVSCatalogTest.removed_at.isnot(None)).group_by(SVSCatalogTest.repository))

    result = []
    for name in sorted(set(configured) | set(rows)):
        row = rows.get(name)
        try:
            repo_config = get_config().get_git_repo_config(name)
        except ValueError:
            # no git_repo section: normal for a retired repository, and for a misconfigured one the
            # refresh already put it in the row's error, which this status shows
            repo_config = None
        error = row.error if row is not None else None
        retired = error == RETIRED_ERROR
        result.append(RepositoryStatus(
            name=name, configured=name in configured,
            git_url=strip_url_credentials(repo_config.git_url) if repo_config is not None else None,
            branch=repo_config.branch if repo_config is not None else None,
            commit=row.commit if row is not None else None,
            refreshed_at=row.refreshed_at if row is not None else None,
            test_count=row.test_count if row is not None else 0,
            skipped_count=row.skipped_count if row is not None else 0,
            removed_count=removed.get(name, 0),
            error=None if retired else error, retired=retired))
    return result


def supported_platforms(test: SVSCatalogTest) -> list[str]:
    """A catalog test's supported_platforms, lower case."""
    return json.loads(test.platforms)


def platform_slugs(test: SVSCatalogTest) -> list[str]:
    """The platforms a run of the test can be on: its supported_platforms as platform slugs,
    sorted."""
    return sorted({normalize_platform(platform) for platform in supported_platforms(test)})
