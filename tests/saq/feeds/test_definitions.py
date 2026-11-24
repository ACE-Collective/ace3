"""Watch definitions from the repositories (docs/FEED_WATCHES.md, *Definitions*)."""

import pytest
from sqlalchemy import select

from saq.database.model import FeedDefinition
from saq.database.pool import get_db
from saq.feeds.definitions import (
    DefinitionError,
    current_commits,
    definition_hash,
    parse_definition,
    prompt_hash,
    read_definitions,
    sync_definitions,
)
from tests.saq.feeds.conftest import EXPLOITED_RULE, PROMPT, REPOSITORY, add_repository


@pytest.mark.unit
@pytest.mark.parametrize("document, message", [
    ({"yara": "rule r { condition: true }"}, "name is required"),
    ({"name": "x"}, "needs a yara rule, a question, or both"),
    ({"name": "x", "question": "q", "queue": "admin"}, "unknown keys: queue"),
    ({"name": "x", "question": 5}, "must be a string"),
    ("just text", "a mapping"),
])
def test_an_unusable_definition(document, message):
    with pytest.raises(DefinitionError, match=message):
        parse_definition(document, REPOSITORY, "definitions/x.yaml", None)


@pytest.mark.unit
def test_the_content_hash_covers_the_rule_and_the_question():
    base = definition_hash("x", "rule", "question")
    assert base == parse_definition({"name": "x", "yara": "rule", "question": "question"}, "r", "p", "c").content_hash
    assert base != definition_hash("x", "rule2", "question")
    assert base != definition_hash("x", "rule", "question2")


@pytest.mark.integration
def test_definitions_are_read_and_copied_into_the_database(definitions_repo):
    definitions_repo.definition("exploited", yara=EXPLOITED_RULE, question="Is a product we run exploited?")
    definitions_repo.definition("broken", file="broken.yaml")
    definitions_repo.write("definitions/notyaml.yaml", "name: [unclosed")
    commit = definitions_repo.commit()

    commits = current_commits()
    assert commits == ((REPOSITORY, commit),)
    loaded = read_definitions(commits)
    assert list(loaded.definitions) == ["exploited"]
    assert loaded.definitions["exploited"].commit == commit
    assert loaded.prompt == PROMPT and loaded.prompt_hash == prompt_hash(PROMPT)
    assert "broken" in loaded.errors

    sync_definitions(loaded, {})
    rows = {row.name: row for row in get_db().execute(select(FeedDefinition)).scalars()}
    assert rows["exploited"].present and rows["exploited"].error is None
    assert rows["exploited"].content_hash == loaded.definitions["exploited"].content_hash
    assert not rows["broken"].present and "needs a yara rule" in rows["broken"].error

    # a definition removed from the repository keeps its row, flagged
    definitions_repo.write("definitions/exploited.yaml", "name: renamed\nquestion: q\n")
    definitions_repo.commit()
    sync_definitions(read_definitions(current_commits()), {"renamed": "the rule does not compile: x"})
    get_db().expire_all()
    rows = {row.name: row for row in get_db().execute(select(FeedDefinition)).scalars()}
    assert not rows["exploited"].present
    assert rows["renamed"].present and rows["renamed"].error == "the rule does not compile: x"


@pytest.mark.integration
def test_a_name_defined_in_two_repositories_keeps_the_first(tmp_path, monkeypatch, caplog):
    first = add_repository(tmp_path, monkeypatch, "first", repositories=["first", "second"])
    second = add_repository(tmp_path, monkeypatch, "second", repositories=["first", "second"])
    first.definition("shared", question="first question")
    second.definition("shared", question="second question")
    first.commit()
    second.commit()

    loaded = read_definitions(current_commits())
    assert loaded.definitions["shared"].question == "first question"
    assert "names must be unique" in loaded.errors["shared"][2]
    assert any(record.levelname == "ERROR" and "is ignored" in record.getMessage() for record in caplog.records)
    # the prompt comes from the first repository, which has none
    assert loaded.prompt is None
