"""validate-yara: requesting an SVS YARA validation from CI and summarizing it."""

import json
import subprocess

import pytest
import requests

from hunt_compiler import yara_validate
from hunt_compiler.ace_client import Connection
from hunt_compiler.yara_validate import ValidateError, main, resolve_commits, summarize, wait_for

BASE = "a" * 40
HEAD = "b" * 40
UUID = "5c0b6f2e-1d3a-4b5c-8d7e-9f0a1b2c3d4e"


def _status(state: str, **values) -> dict:
    return {
        "uuid": UUID, "state": state, "error": None, "repository": "signatures", "base_sha": BASE, "head_sha": HEAD,
        "branch": "feature", "diffed": None, "counts": None, "rules": {}, "compile_errors": [],
        "ruleset_error": None, "report_path": f"/ace/signatures/validations/{UUID}", **values,
    }


COMPLETED = _status(
    "completed", diffed=True,
    counts={"regression": 2, "new_fp_other_rule": 1, "improvement": 0, "known_fp": 4},
    rules={"regression": [{"rule_uuid": "r1", "rule_name": "evil_doc", "count": 2}],
           "new_fp_other_rule": [{"rule_uuid": "r2", "rule_name": "generic_pe", "count": 1}]},
    compile_errors=[{"file": "yara/acme/broken.yar", "error": "syntax error"}])


class FakeResponse:
    def __init__(self, status_code: int, body: dict):
        self.status_code = status_code
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


class FakeACE:
    """Answers the POST, then each GET of the status in turn."""

    def __init__(self, post: FakeResponse, statuses: list):
        self.post = post
        self.statuses = list(statuses)
        self.calls = []

    def request(self, connection, method, path, **kwargs):
        self.calls.append((method, path, kwargs.get("json")))
        if method == "POST":
            return self.post
        answer = self.statuses.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture
def fake_ace(monkeypatch):
    def _install(post: FakeResponse, statuses: list = ()) -> FakeACE:
        ace = FakeACE(post, statuses)
        monkeypatch.setattr(Connection, "request", lambda self, method, path, **kwargs: ace.request(self, method, path, **kwargs))
        monkeypatch.setattr(yara_validate.time, "sleep", lambda seconds: None)
        return ace

    return _install


ARGS = ["--repository", "signatures", "--base", BASE, "--head", HEAD, "--branch", "feature", "-k", "key",
        "-u", "ace.example", "--poll-interval", "1"]


def test_it_requests_waits_and_writes_the_summary(fake_ace, tmp_path, capsys):
    ace = fake_ace(FakeResponse(202, _status("queued")),
                   [FakeResponse(200, _status("running")), FakeResponse(200, COMPLETED)])
    summary_file = tmp_path / "summary.md"

    assert main([*ARGS, "--pr-url", "https://git.example/pr/7", "--summary-file", str(summary_file)]) == 0

    assert ace.calls[0] == ("POST", yara_validate.API_PATH, {
        "repository": "signatures", "base_sha": BASE, "head_sha": HEAD, "branch": "feature",
        "pr_url": "https://git.example/pr/7"})
    assert [call[1] for call in ace.calls[1:]] == [f"{yara_validate.API_PATH}{UUID}/status"] * 2
    summary = summary_file.read_text()
    assert summary == capsys.readouterr().out.rstrip("\n") + "\n"
    assert f"(https://ace.example/ace/signatures/validations/{UUID})" in summary
    assert "### Regressions: 2" in summary
    assert "- evil_doc (`r1`): 2 sample(s)" in summary
    assert "### New false positives on another rule's sample: 1" in summary
    assert "graded false positives for other rules" in summary
    assert "`yara/acme/broken.yar`: syntax error" in summary
    assert "never blocks" in summary


def test_a_failed_or_unfinished_validation_still_exits_0(fake_ace, capsys):
    fake_ace(FakeResponse(200, _status("failed", error="commit x is not in repository signatures")))
    assert main(ARGS) == 0
    assert "could not run: commit x is not in repository" in capsys.readouterr().out

    fake_ace(FakeResponse(202, _status("queued")), [FakeResponse(200, _status("running"))] * 50)
    assert main([*ARGS, "--timeout", "0"]) == 0
    assert "still queued after 0 seconds" in capsys.readouterr().out


def test_a_refused_request_exits_2(fake_ace, capsys):
    fake_ace(FakeResponse(403, {"detail": "permission svs:validate required"}))
    assert main(ARGS) == 2
    assert "ACE answered 403: permission svs:validate required" in capsys.readouterr().err


def test_missing_arguments_exit_2(monkeypatch, capsys):
    monkeypatch.delenv("ACE_API_KEY", raising=False)
    monkeypatch.delenv("ACE_SVS_REPOSITORY", raising=False)
    assert main(["--base", BASE, "--head", HEAD, "--branch", "feature", "-k", "key"]) == 2
    assert "--repository is required" in capsys.readouterr().err
    assert main(["--repository", "signatures", "--base", BASE, "--head", HEAD, "--branch", "feature"]) == 2
    assert "API key is not set" in capsys.readouterr().err


def test_connection_errors_while_polling_are_retried():
    statuses = [requests.exceptions.ConnectionError("reset"), FakeResponse(200, COMPLETED)]
    ace = FakeACE(FakeResponse(202, {}), statuses)
    connection = Connection(remote_host="ace.example", api_key="key")
    clock = iter(range(100))
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(Connection, "request", lambda self, method, path, **kwargs: ace.request(self, method, path, **kwargs))
        status = wait_for(connection, _status("queued"), 60, 1, sleep=lambda seconds: None, clock=lambda: next(clock))

    assert status["state"] == "completed"


def test_a_clean_validation_says_so():
    summary = summarize(_status("completed", diffed=True, counts={"regression": 0, "known_fp": 3}), "ace.example", 3600)
    assert "No regressions and no new false positives." in summary
    assert "###" not in summary


def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
                          env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                               "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_GLOBAL": "/dev/null",
                               "GIT_CONFIG_NOSYSTEM": "1", "PATH": "/usr/bin:/bin"}).stdout.strip()


def test_the_base_defaults_to_the_merge_base_with_the_target_branch(tmp_path):
    origin, work = tmp_path / "origin", tmp_path / "work"
    origin.mkdir()
    work.mkdir()
    _git(origin, "init", "--bare", "--quiet", "-b", "main")
    _git(work, "init", "--quiet", "-b", "main")
    _git(work, "remote", "add", "origin", str(origin))
    _git(work, "commit", "--quiet", "--allow-empty", "-m", "base")
    _git(work, "push", "--quiet", "origin", "main")
    base = _git(work, "rev-parse", "HEAD")
    _git(work, "checkout", "--quiet", "-b", "feature")
    _git(work, "commit", "--quiet", "--allow-empty", "-m", "change")
    head = _git(work, "rev-parse", "HEAD")
    _git(work, "fetch", "--quiet", "origin")

    args = yara_validate.parse_args(["--repository", "signatures", "--git-dir", str(work), "--target-branch", "main"])
    args.branch = None
    assert resolve_commits(args) == (base, head, "feature")

    args.head = "no-such-ref"
    with pytest.raises(ValidateError, match="git rev-parse"):
        resolve_commits(args)
