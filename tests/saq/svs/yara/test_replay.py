"""A whole validation: a real repository, the real sandbox and real samples (saq.svs.yara.replay)."""

import os
import uuid
from unittest.mock import patch

import pytest

from saq.cli.commands.svs import print_report
from saq.configuration.config import get_config
from saq.environment import get_data_dir
from saq.sandbox.runner import landlock_available
from saq.svs.yara.diff import Category, Outcome
from saq.svs.yara.replay import ReplayError, run_replay
from tests.saq.svs.yara.conftest import REPOSITORY, rule, stored_sample

pytestmark = pytest.mark.skipif(not landlock_available(), reason="landlock is unavailable")

R1, R2, R3, R4, R5, R6, R7, BROKEN = (str(uuid.uuid4()) for _ in range(8))


def _work_dirs() -> list[str]:
    root = os.path.join(get_data_dir(), get_config().svs.yara.work_dir)
    return os.listdir(root) if os.path.isdir(root) else []


def _rows(result) -> dict:
    return {(row.sha256, row.rule_uuid): row for row in result.rows}


@pytest.mark.integration
def test_a_validation_reports_what_the_change_does(svs_repository):
    a = stored_sample("DELIVERY", b"alpha evil", [R1])
    b = stored_sample("FALSE_POSITIVE", b"beta bad", [R2])
    c = stored_sample("DELIVERY", b"gamma", [R3])
    # two rules fired on the alert: their TP labels are unconfirmed (inherited_multi)
    d = stored_sample("DELIVERY", b"delta", [R6, R7])

    base = svs_repository.commit({"yara/acme/rules.yar": (
        rule("one", R1, '$a = "evil"') + rule("two", R2, '$a = "bad"') + rule("three", R3, '$a = "gamma"')
        + rule("six", R6, '$a = "delta"') + rule("seven", R7, '$a = "delta"'))})
    head = svs_repository.commit({
        "yara/acme/rules.yar": (
            rule("one", R1, '$a = "nothing here"') + rule("two", R2, '$a = "zzz"') + rule("three", R3, '$a = "gamma"')
            + rule("four", R4, '$a = "bad"') + rule("seven", R7, '$a = "epsilon"')),
        "yara/beta/new.yar": rule("five", R5, '$a = "evil"'),
        "yara/acme/broken.yar": rule("broken", BROKEN, '$a = "x"', condition="nope"),
        "yara/acme/deeper/nested.yar": rule("nested", str(uuid.uuid4()), '$a = "x"'),
        "yara/acme/no_uuid.yar": rule("anonymous", None, '$a = "x"'),
    }, branch="feature")

    result = run_replay(REPOSITORY, base, head, branch="feature")

    assert result.diffed
    rows = _rows(result)
    assert rows[(a, R1)].category == Category.REGRESSION
    assert (rows[(a, R1)].base, rows[(a, R1)].head) == (Outcome.MATCH, Outcome.MISS)
    assert rows[(b, R2)].category == Category.IMPROVEMENT
    assert rows[(b, R4)].category == Category.NEW_FP_OTHER_RULE
    assert rows[(a, R5)].category == Category.NEW_MATCH_REAL_HIT
    assert rows[(a, R5)].namespace == "beta"
    assert rows[(d, R6)].category == Category.RULE_REMOVED
    assert rows[(d, R7)].category == Category.REGRESSION_UNCONFIRMED
    assert (c, R3) not in rows
    assert result.counts["unchanged"] == 1
    assert sum(result.counts.values()) == 7

    (error,) = result.head.file_errors
    assert (error.file, [ref.uuid for ref in error.dropped]) == ("yara/acme/broken.yar", [BROKEN])
    assert [item.path for item in result.head.not_loaded] == ["yara/acme/deeper/nested.yar"]
    assert result.base.namespaces == ["acme"] and result.head.namespaces == ["acme", "beta"]
    # a rule in a file that does not compile is still in head's source
    assert {ref.uuid for ref in result.added_rules} == {R4, R5, BROKEN}
    assert {ref.uuid for ref in result.removed_rules} == {R6}
    assert {ref.uuid for ref in result.changed_rules} == {R1, R2, R7}
    assert [(item["name"], item["reason"]) for item in result.not_testable] == [("anonymous", "no uuid")]
    assert (result.files, result.samples) == (4, 5)
    assert set(result.head.timings) == {"acme", "beta"}
    assert _work_dirs() == []


@pytest.mark.integration
def test_retired_samples_are_only_counted(svs_repository):
    a = stored_sample("DELIVERY", b"alpha evil", [R1])
    base = svs_repository.commit({"yara/acme/rules.yar": rule("one", R1, '$a = "evil"')})
    head = svs_repository.commit({"yara/acme/rules.yar": rule("one", R1, '$a = "nothing"')})

    result = run_replay(REPOSITORY, base, head, retired=frozenset({(a, R1)}))
    assert result.rows == []
    assert result.counts["retired"] == 1


@pytest.mark.integration
def test_a_head_that_would_not_load_is_not_compared(svs_repository, capsys):
    stored_sample("DELIVERY", b"alpha evil", [R1])
    base = svs_repository.commit({"yara/acme/rules.yar": rule("one", R1, '$a = "evil"')})
    head = svs_repository.commit({"yara/acme/again.yar": rule("one", R2, '$a = "evil"')})

    result = run_replay(REPOSITORY, base, head)
    assert not result.diffed
    assert "duplicated identifier" in result.head.ruleset_error
    assert result.base.loads and result.rows == []

    print_report(result)
    assert "the ruleset would not load" in capsys.readouterr().out


@pytest.mark.integration
def test_the_report_prints(svs_repository, capsys):
    stored_sample("DELIVERY", b"alpha evil", [R1])
    base = svs_repository.commit({"yara/acme/rules.yar": rule("one", R1, '$a = "evil"')})
    head = svs_repository.commit({"yara/acme/rules.yar": rule("one", R1, '$a = "nothing"')})

    print_report(run_replay(REPOSITORY, base, head))
    output = capsys.readouterr().out
    assert "Regressions (1):" in output
    assert "one" in output


@pytest.mark.integration
def test_the_working_directory_is_deleted_when_the_scan_fails(svs_repository):
    stored_sample("DELIVERY", b"alpha evil", [R1])
    sha = svs_repository.commit({"yara/acme/rules.yar": rule("one", R1, '$a = "evil"')})

    with patch("saq.svs.yara.replay._run_child", side_effect=ReplayError("the scan failed")):
        with pytest.raises(ReplayError, match="the scan failed"):
            run_replay(REPOSITORY, sha, sha)

    assert _work_dirs() == []


@pytest.mark.integration
def test_an_unknown_commit_fails(svs_repository):
    sha = svs_repository.commit({"yara/acme/rules.yar": rule("one", R1, '$a = "evil"')})
    with pytest.raises(ReplayError, match="is not in repository"):
        run_replay(REPOSITORY, sha, "0" * 40)

    with pytest.raises(ReplayError, match="not a commit id"):
        run_replay(REPOSITORY, sha, "main")

    with pytest.raises(ReplayError, match="not in svs.yara.repositories"):
        run_replay("elsewhere", sha, sha)
