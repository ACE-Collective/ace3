"""Watch definitions (docs/FEED_WATCHES.md, *Definitions*).

A definition is a YAML file under definitions/ in one of the git repositories feeds.repositories names
(git_repo_* sections, kept checked out by service_git): a name, an optional YARA rule (yara) and an
optional question, at least one of the two. Its content hash covers all three, so an edit to the rule
or the question is a new watch version. The LLM system prompt is system_prompt.md at the root of
feeds.prompt_repository (the first repository by default); its version is the hash of the file.

service_feed_watch reads the repositories whenever a commit moves and copies what it read into
feed_definitions (sync_definitions), which is all the API and the GUI read. Nothing here compiles a
rule: saq.feeds.matching does, in the service only.
"""

import glob
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

import yaml
from sqlalchemy import select, update

from saq.configuration.config import get_config
from saq.database.model import FeedDefinition
from saq.database.pool import get_db
from saq.git import get_commit_hash
from saq.util import abs_path

DEFINITIONS_DIR = "definitions"
PROMPT_FILE = "system_prompt.md"
NAME_MAX = 256
MAX_DEFINITION_BYTES = 1024 * 1024


class DefinitionError(ValueError):
    """A definition file that can't be used; the message says why."""


@dataclass(frozen=True)
class Definition:
    name: str
    repository: str
    path: str
    commit: Optional[str]
    yara: Optional[str]
    question: Optional[str]

    @property
    def content_hash(self) -> str:
        return definition_hash(self.name, self.yara, self.question)


@dataclass
class DefinitionSet:
    definitions: dict[str, Definition] = field(default_factory=dict)
    # name -> (repository, path, why the definition is not usable as it stands)
    errors: dict[str, tuple[str, str, str]] = field(default_factory=dict)
    prompt: Optional[str] = None
    prompt_hash: Optional[str] = None
    # what the set was read from: (repository, commit) for each repository
    commits: tuple = ()


def definition_hash(name: str, yara_source: Optional[str], question: Optional[str]) -> str:
    return hashlib.sha256(json.dumps([name, yara_source or None, question or None],
                                     separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def prompt_hash(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def _text(value) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise DefinitionError(f"must be a string, not {type(value).__name__}")
    return value.strip() or None


def parse_definition(document, repository: str, path: str, commit: Optional[str]) -> Definition:
    """A definition from its parsed YAML. Raises DefinitionError."""
    if not isinstance(document, dict):
        raise DefinitionError("a definition is a mapping with name, and yara or question")

    unknown = set(document) - {"name", "yara", "question", "description"}
    if unknown:
        raise DefinitionError(f"unknown keys: {', '.join(sorted(unknown))}")

    name = _text(document.get("name"))
    if not name:
        raise DefinitionError("name is required")
    if len(name) > NAME_MAX:
        raise DefinitionError(f"name is longer than {NAME_MAX} characters")

    try:
        yara_source = _text(document.get("yara"))
        question = _text(document.get("question"))
    except DefinitionError as e:
        raise DefinitionError(f"{name}: yara and question {e}") from None

    if not yara_source and not question:
        raise DefinitionError(f"{name}: a definition needs a yara rule, a question, or both")

    return Definition(name=name, repository=repository, path=path, commit=commit, yara=yara_source,
                      question=question)


def repository_checkout(repository: str) -> str:
    """The local checkout of a repository feeds.repositories names. Raises DefinitionError."""
    try:
        repo_config = get_config().get_git_repo_config(repository)
    except ValueError:
        raise DefinitionError(f"feeds.repositories names {repository}, but no git_repo section is named {repository}") from None
    return abs_path(repo_config.local_path)


def current_commits() -> tuple:
    return tuple((repository, get_commit_hash(repository_checkout_or_none(repository)))
                 for repository in get_config().feeds.repositories)


def repository_checkout_or_none(repository: str) -> Optional[str]:
    try:
        path = repository_checkout(repository)
    except DefinitionError:
        # read_definitions logs a repository it can't find, once per read
        return None
    return path if os.path.isdir(path) else None


def read_definitions(commits: tuple) -> DefinitionSet:
    """Every definition and the prompt, as the checkouts hold them now. A file that can't be used is
    logged at ERROR; one whose name it can read is also kept as that name's error."""
    result = DefinitionSet(commits=commits)
    for repository, commit in commits:
        checkout = repository_checkout_or_none(repository)
        if checkout is None:
            logging.error("feed watch definitions repository %s has no checkout yet; is service_git running?",
                          repository, extra={"repository": repository})
            continue

        for path in sorted(glob.glob(os.path.join(checkout, DEFINITIONS_DIR, "**", "*.y*ml"), recursive=True)):
            relative = os.path.relpath(path, checkout)
            extra = {"repository": repository, "path": relative}
            try:
                if os.path.getsize(path) > MAX_DEFINITION_BYTES:
                    raise DefinitionError(f"larger than {MAX_DEFINITION_BYTES} bytes")
                with open(path, "rb") as fp:
                    document = yaml.safe_load(fp)
                definition = parse_definition(document, repository, relative, commit)
            except (OSError, yaml.YAMLError, DefinitionError) as e:
                logging.error("feed watch definition %s in %s can't be used: %s", relative, repository, e, exc_info=e,
                              extra=extra)
                if isinstance(document_name := _name_of(path), str) and document_name not in result.definitions:
                    result.errors[document_name] = (repository, relative, str(e))
                continue

            if definition.name in result.definitions:
                first = result.definitions[definition.name]
                logging.error("feed watch definition %s is defined in %s/%s and again in %s/%s; the second is ignored",
                              definition.name, first.repository, first.path, repository, relative, extra=extra)
                result.errors.setdefault(definition.name, (
                    first.repository, first.path, f"also defined in {repository}/{relative}, which is ignored: names must be unique"))
                continue

            result.definitions[definition.name] = definition

    repositories = get_config().feeds.repositories
    prompt_repository = get_config().feeds.prompt_repository or (repositories[0] if repositories else None)
    checkout = repository_checkout_or_none(prompt_repository) if prompt_repository else None
    if checkout is not None:
        try:
            with open(os.path.join(checkout, PROMPT_FILE), "r", encoding="utf-8") as fp:
                result.prompt = fp.read()
            result.prompt_hash = prompt_hash(result.prompt)
        except FileNotFoundError:
            # no prompt: questions stay pending, which the classifier logs at ERROR
            pass
        except (OSError, UnicodeDecodeError) as e:
            logging.error("unable to read the feed watch system prompt %s in %s: %s", PROMPT_FILE, prompt_repository, e, exc_info=e,
                          extra={"repository": prompt_repository, "path": PROMPT_FILE})

    return result


def _name_of(path: str) -> Optional[str]:
    """The name a definition file gives, if any can be read: its error then shows on that name."""
    try:
        with open(path, "rb") as fp:
            document = yaml.safe_load(fp)
    except (OSError, yaml.YAMLError):
        # the caller already logged why the file can't be read
        return None
    if isinstance(document, dict) and isinstance(document.get("name"), str):
        return document["name"].strip()[:NAME_MAX] or None
    return None


def sync_definitions(definitions: DefinitionSet, compile_errors: dict[str, str]) -> None:
    """Makes feed_definitions what definitions holds: a definition no longer there keeps its row with
    present false, so a watch that names it is flagged. compile_errors: name -> why its rule does not
    compile."""
    db = get_db()
    rows = {row.name: row for row in db.execute(select(FeedDefinition)).scalars().all()}
    errors = {name: message for name, (_, _, message) in definitions.errors.items()}
    errors.update(compile_errors)

    for name, definition in definitions.definitions.items():
        row = rows.get(name)
        if row is None:
            row = FeedDefinition(name=name)
            db.add(row)
        row.repository = definition.repository
        row.path = definition.path
        row.commit = definition.commit
        row.content_hash = definition.content_hash
        row.yara = definition.yara
        row.question = definition.question
        row.present = True
        row.error = errors.get(name)

    for name, error in errors.items():
        if name in definitions.definitions:
            continue
        row = rows.get(name)
        if row is None:
            # a file whose name could be read but that can't be used: listed so its error shows
            repository, path, _ = definitions.errors[name]
            db.add(FeedDefinition(name=name, repository=repository, path=path, present=False, error=error))
        else:
            row.present = False
            row.error = error

    gone = [name for name in rows if name not in definitions.definitions and name not in errors]
    if gone:
        db.execute(update(FeedDefinition).where(FeedDefinition.name.in_(gone))
                   .values(present=False, error="no longer in the definitions repositories"))
    db.commit()
