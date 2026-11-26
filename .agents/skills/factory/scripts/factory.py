#!/usr/bin/env python3
"""The /factory skill's deterministic layer: ticket and PR state, claiming, worktrees, and
every write to GitHub or Azure DevOps. Runs on the host, where gh and az are logged in (az through
az login or AZURE_DEVOPS_EXT_PAT).
Stdlib only.

    factory.py doctor                       check what a run needs, and say how to fix what is missing
    factory.py labels                       create the factory:* labels on the ace3 repo
    factory.py ready                        list the tickets labeled factory:ready
    factory.py ticket TICKET                the ticket's description and its maintainers' comments
    factory.py state TICKET                 the ticket, its PRs, their reviews, and the next task
    factory.py claim TICKET                 assign the ticket to you and mark it in progress
    factory.py release TICKET --to STATE [--body-file F] [--repo NAME]
                                            hand the ticket back: needs-info, needs-human or ready
    factory.py worktree TICKET [--slug S] [--internal NAME ...]
                                            create or reuse the ticket's worktree; prints its path
    factory.py worktree-remove TICKET       remove it once everything in it is pushed
    factory.py base-check TICKET [--repo NAME]
                                            whether the branch needs a rebase before review or promote
    factory.py checks TICKET --repo NAME    run an internal repo's [[check]]s on what the branch changes
    factory.py push TICKET [--repo NAME]    check (for ace3) and push the ticket's branch
    factory.py pr-create TICKET --repo NAME --title T --body-file F
    factory.py pr-body TICKET --repo NAME --body-file F
    factory.py pr-labels TICKET --repo NAME [--add L ...] [--remove L ...]
                                            label the PR from the repo's own labels; prints them
    factory.py comment TICKET --kind KIND [--repo NAME | --on-ticket] --body-file F
    factory.py post-review TICKET --repo NAME --bundle DIR
    factory.py backlog TICKET --repo NAME --bundle DIR
                                            a finished round's pre-existing findings and new design
                                            flaws, each with the issues that may already be it
    factory.py file-backlog TICKET --repo NAME --bundle DIR
                                            file the ones $B/backlog.json judged new, record the rest
    factory.py comments TICKET --repo NAME  the human comments rework has to answer
    factory.py promote TICKET               mark every PR ready, once each has shipped at its head
    factory.py handoff FILE                 validate a task's result against the live state
    factory.py issue-create --title T --body-file F [--label L ...]
                                            file an ace3 issue (checked like every public write)
    factory.py retro-data [--since DATE] [--mark]
                                            what happened on the factory PRs merged since the last retro

A TICKET is an ace3 GitHub issue (1234 or #1234) or an Azure DevOps work item (ado:5678).
Its branch, in every repo it touches, is factory/<1234|ado-5678>-<slug>.

State lives on the ticket and the PRs. Every comment the factory posts ends with a hidden
marker, <!-- factory:KIND {json} -->; a review's carries the round, the head it reviewed,
the verdict and the open finding ids. A comment without a marker from a maintainer
(GitHub author association OWNER, MEMBER or COLLABORATOR; on Azure DevOps, any person, since the
repos are private) is a human comment rework must answer. Every other comment is ignored.

Writes to the public ace3 repo (pushes, PR titles and bodies, comments) first go through
public_text.py, and nothing is published when it finds a match or cannot run.
"""

import argparse
import base64
import fnmatch
import html
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import tomllib
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import public_text  # noqa: E402  (a sibling script, not a package)

# /ace-review's script, for the issue bodies it writes the same way when it files them itself
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "ace-review", "scripts"))
import findings  # noqa: E402

CORE = "ace3"
LABELS = {
    "factory:ready": ("0e8a16", "A maintainer has cleared this issue for /factory"),
    "factory:in-progress": ("fbca04", "A /factory run has claimed this issue"),
    "factory:needs-info": ("d93f0b", "/factory stopped: the issue needs an answer from a maintainer"),
    "factory:needs-human": ("b60205", "/factory stopped: a human has to take it from here"),
}
READY, IN_PROGRESS, NEEDS_INFO, NEEDS_HUMAN = LABELS
STOP_LABELS = {"needs-info": NEEDS_INFO, "needs-human": NEEDS_HUMAN, "ready": READY}
# the people with write access to the repo
MAINTAINERS = {"OWNER", "MEMBER", "COLLABORATOR"}
REVIEW_CAP = 3
VERDICTS = ("ship", "fix-first", "rework")
KINDS = ("review", "reply", "question", "stop", "note")
TASKS = ("implement", "review", "rework", "promote")
NEXT_STATES = ("review", "rework", "promote", "needs-info", "needs-human", "done")
MARKER = re.compile(r"<!-- factory:([a-z-]+)( \{.*?\})? -->", re.DOTALL)
TIMEOUT = 120
CONFIG = os.path.join(".factory", "config.toml")
ADO_API = "7.1"
ADO_COMMENTS_API = "7.1-preview"  # the work item comments API has no released version
ADO_DESCRIPTION_LIMIT = 4000
ADO_CLOSED_STATES = ("Closed", "Done", "Removed", "Resolved")


class FactoryError(Exception):
    pass


# ---------------------------------------------------------------- running things

def run(cmd: list[str], cwd: str | None = None, stdin: str | None = None, timeout: int = TIMEOUT, check: bool = True) -> str:
    try:
        result = subprocess.run(cmd, cwd=cwd, input=stdin, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise FactoryError(f"{' '.join(cmd[:3])}: {e}") from e
    if check and result.returncode:
        raise FactoryError(f"{' '.join(cmd)} failed ({result.returncode}): {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def run_json(cmd: list[str], **kwargs):
    out = run(cmd, **kwargs)
    return json.loads(out) if out.strip() else None


def git(repo: str, *args: str, check: bool = True) -> str:
    return run(["git", "-C", repo, *args], check=check)


# ---------------------------------------------------------------- tickets and repos

def parse_ticket(text: str) -> dict:
    text = text.strip()
    if match := re.fullmatch(r"#?(\d+)", text):
        number = int(match.group(1))
        return {"ref": str(number), "kind": "github", "id": number, "prefix": f"factory/{number}-"}
    if match := re.fullmatch(r"ado:(\d+)", text, re.IGNORECASE):
        number = int(match.group(1))
        return {"ref": f"ado:{number}", "kind": "ado", "id": number, "prefix": f"factory/ado-{number}-"}
    raise FactoryError(f"not a ticket: {text!r} (an issue number, or ado:<work item id>)")


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40].rstrip("-") or "change"


def main_checkout() -> str:
    """The main checkout of the ace3 repo this script belongs to, from any worktree of it."""
    here = os.path.dirname(os.path.abspath(__file__))
    common = git(here, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    return os.path.dirname(common)


def load_config(path: str) -> dict:
    try:
        with open(path, "rb") as fp:
            config = tomllib.load(fp)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise FactoryError(f"cannot read {path}: {e}") from e
    problems = []
    for key in ("organization", "project", "repository"):
        if not config.get("azure_devops", {}).get(key):
            problems.append(f"azure_devops.{key}")
    for index, check in enumerate(config.get("check", [])):
        if not check.get("name") or not check.get("command"):
            problems.append(f"check {index + 1} needs name and command")
        if not all(isinstance(p, str) for p in check.get("paths", [])):
            problems.append(f"check {index + 1} paths is a list of globs")
    if problems:
        raise FactoryError(f"{path}: missing or bad {', '.join(problems)}")
    return config


def repos(main: str) -> dict[str, dict]:
    """ace3, and each internal repo whose main checkout commits a .factory/config.toml."""
    found = {CORE: {"name": CORE, "path": main, "host": "github", "public": True}}
    for name, path in public_text.internal_repos(main).items():
        config_path = os.path.join(path, CONFIG)
        if os.path.exists(config_path):
            found[name] = {"name": name, "path": path, "host": "azure-devops", "public": False, "config": load_config(config_path)}
    return found


def github_slug(main: str) -> str:
    return run(["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"], cwd=main).strip()


def base_branch(repo_path: str) -> str:
    out = git(repo_path, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD", check=False).strip()
    return out.removeprefix("origin/") or "main"


def remote_branches(repo_path: str, prefix: str) -> list[str]:
    out = git(repo_path, "ls-remote", "--heads", "origin", f"refs/heads/{prefix}*")
    return sorted(line.split("refs/heads/", 1)[1] for line in out.splitlines() if "refs/heads/" in line)


# ---------------------------------------------------------------- markers and comments

def marker(kind: str, data: dict | None = None) -> str:
    if kind not in KINDS:
        raise FactoryError(f"unknown marker kind {kind}")
    payload = f" {json.dumps(data, sort_keys=True)}" if data else ""
    return f"<!-- factory:{kind}{payload} -->"


def read_marker(body: str) -> tuple[str, dict] | None:
    """The last factory marker in a comment, if it has one."""
    found = list(MARKER.finditer(body or ""))
    if not found:
        return None
    kind, payload = found[-1].group(1), found[-1].group(2)
    try:
        return kind, json.loads(payload) if payload else {}
    except json.JSONDecodeError:
        # a marker someone edited by hand: its kind still says whose comment it is, and a review
        # without a head reads as not yet reviewed, so the PR is simply reviewed again
        return kind, {}


def classify(comments: list[dict]) -> list[dict]:
    """Comments in time order, each marked factory (with its kind and data), human, or ignored.

    Each comment is {author, trusted, body, at, url}; trusted means a maintainer wrote it."""
    out = []
    for comment in sorted(comments, key=lambda c: c["at"]):
        found = read_marker(comment["body"])
        if not comment["trusted"]:
            role = "ignored"
        elif found:
            role = "factory"
        else:
            role = "human"
        out.append({**comment, "role": role, "kind": found[0] if found and role == "factory" else None,
                    "data": found[1] if found and role == "factory" else None})
    return out


def pr_progress(comments: list[dict], cap: int = REVIEW_CAP) -> dict:
    """What the factory comments on one PR say: the last review, rounds since the last stop, and
    whether humans or a rework reply have spoken since it."""
    reviews, last_factory, humans_after, rounds = [], None, [], 0
    for comment in classify(comments):
        if comment["role"] == "factory":
            last_factory = comment
            humans_after = []
            if comment["kind"] == "review":
                reviews.append(comment)
                rounds += 1
            elif comment["kind"] == "stop":
                # a human takes over at a stop; the cap counts again from there
                rounds = 0
        elif comment["role"] == "human":
            humans_after.append(comment)
    last = reviews[-1]["data"] if reviews else None
    return {
        "last_review": last,
        "rounds": rounds,
        "cap_reached": rounds >= cap,
        "replied_since_review": bool(last_factory and last_factory["kind"] == "reply" and reviews and last_factory is not reviews[-1]),
        "human_comments": [{"author": c["author"], "at": c["at"], "url": c["url"], "body": c["body"]} for c in humans_after],
    }


def pr_step(pr: dict) -> str:
    """The next task for one PR: review, rework, promote, shipped, needs-human or closed."""
    if pr["state"] != "open":
        return "closed"
    progress = pr["progress"]
    last = progress["last_review"]
    if progress["human_comments"]:
        return "rework"
    if last is None or last.get("head") != pr["head"] or progress["replied_since_review"]:
        if progress["cap_reached"] and last and last.get("verdict") != "ship":
            return "needs-human"
        return "review"
    if last.get("verdict") == "ship":
        return "promote" if pr["draft"] else "shipped"
    # only a maintainer can accept or reject a round's rule changes, so rework would have nothing to fix
    if last.get("held") == "rules" and not last.get("open"):
        return "needs-human"
    return "needs-human" if progress["cap_reached"] else "rework"


def ticket_step(ticket: dict, prs: list[dict], branches: dict[str, list[str]], me: str) -> dict:
    """The next task for the whole ticket, and which repo's PR it is for."""
    labels, assignees = set(ticket["labels"]), ticket["assignees"]
    if ticket["closed"]:
        return {"next": "done", "why": "the ticket is closed"}
    # a maintainer who answered labels the ticket factory:ready again, which outranks the old stop
    if NEEDS_INFO in labels and READY not in labels:
        return {"next": "needs-info", "why": "waiting for a maintainer to answer on the ticket and label it factory:ready again"}
    if NEEDS_HUMAN in labels:
        return {"next": "needs-human", "why": "a human has to take it from here; remove factory:needs-human to let /factory continue"}
    others = [a for a in assignees if a.lower() != me.lower()]
    if others and me.lower() not in (a.lower() for a in assignees):
        return {"next": "blocked", "why": f"claimed by {', '.join(others)}"}
    open_prs = [pr for pr in prs if pr["state"] == "open"]
    if not open_prs:
        if any(pr["state"] == "merged" for pr in prs):
            return {"next": "done", "why": "its PRs have merged"}
        if READY in labels or IN_PROGRESS in labels or any(branches.values()):
            return {"next": "implement", "why": "no PR yet" + (" (resuming the pushed branch)" if any(branches.values()) else "")}
        return {"next": "not-ready", "why": f"not labeled {READY}"}
    steps = {pr["repo"]: pr_step(pr) for pr in open_prs}
    for wanted in ("needs-human", "rework", "review"):
        for repo, step in steps.items():
            if step == wanted:
                return {"next": wanted, "repo": repo, "why": f"{repo} PR: {wanted}"}
    if any(step == "promote" for step in steps.values()):
        return {"next": "promote", "why": "every open PR shipped at its current head"}
    return {"next": "done", "why": "every open PR is ready for human review"}


# ---------------------------------------------------------------- GitHub

def gh(main: str, *args: str, stdin: str | None = None) -> str:
    return run(["gh", *args], cwd=main, stdin=stdin)


def gh_me(main: str) -> str:
    return gh(main, "api", "user", "--jq", ".login").strip()


def gh_lines(main: str, path: str, jq: str) -> list[dict]:
    out = gh(main, "api", "--paginate", path, "--jq", jq)
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def gh_ticket(main: str, slug: str, number: int) -> dict:
    issue = json.loads(gh(main, "issue", "view", str(number), "--repo", slug, "--json", "number,title,state,labels,assignees,url,body"))
    return {"ref": str(number), "title": issue["title"], "url": issue["url"], "body": issue["body"],
            "closed": issue["state"] != "OPEN", "labels": [l["name"] for l in issue["labels"]],
            "assignees": [a["login"] for a in issue["assignees"]]}


GH_COMMENT_JQ = '.[] | {author: .user.login, association: .author_association, body: (.body // ""), at: (.created_at // .submitted_at), url: .html_url}'


def gh_comments(main: str, slug: str, number: int, include_pr: bool) -> list[dict]:
    raw = gh_lines(main, f"repos/{slug}/issues/{number}/comments", GH_COMMENT_JQ)
    if include_pr:
        raw += gh_lines(main, f"repos/{slug}/pulls/{number}/comments", GH_COMMENT_JQ)
        # a review with no body is only the container of its inline comments
        raw += [r for r in gh_lines(main, f"repos/{slug}/pulls/{number}/reviews", GH_COMMENT_JQ) if r["body"].strip()]
    return [{"author": c["author"], "trusted": c["association"] in MAINTAINERS, "body": c["body"], "at": c["at"], "url": c["url"]} for c in raw]


def gh_prs(main: str, slug: str, branches: list[str]) -> list[dict]:
    prs = []
    for branch in branches:
        found = json.loads(gh(main, "pr", "list", "--repo", slug, "--head", branch, "--state", "all",
                              "--json", "number,url,isDraft,headRefOid,state,baseRefName,title,isCrossRepository"))
        # --head matches the branch name in any fork too, and a fork's PR is never the factory's
        for pr in (p for p in found if not p["isCrossRepository"]):
            prs.append({"repo": CORE, "host": "github", "id": pr["number"], "url": pr["url"], "branch": branch, "title": pr["title"],
                        "draft": pr["isDraft"], "head": pr["headRefOid"], "base": pr["baseRefName"],
                        "state": {"OPEN": "open", "MERGED": "merged"}.get(pr["state"], "closed"),
                        "progress": pr_progress(gh_comments(main, slug, pr["number"], include_pr=True))})
    return prs


# ---------------------------------------------------------------- Azure DevOps

def az(*args: str) -> object:
    return run_json(["az", *args, "-o", "json"])


def ado_args(repo: dict) -> list[str]:
    return ["--org", repo["config"]["azure_devops"]["organization"]]


def ado_me(repo: dict) -> str:
    # az devops authenticates with AZURE_DEVOPS_EXT_PAT, but az account show knows only an az login session
    pat = os.environ.get("AZURE_DEVOPS_EXT_PAT")
    if not pat:
        return run(["az", "account", "show", "--query", "user.name", "-o", "tsv"]).strip()
    url = repo["config"]["azure_devops"]["organization"].rstrip("/") + "/_apis/connectionData"
    token = base64.b64encode(f":{pat}".encode()).decode()
    request = urllib.request.Request(url, headers={"Authorization": f"Basic {token}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            data = json.load(response)
        return data["authenticatedUser"]["properties"]["Account"]["$value"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise FactoryError(f"reading who AZURE_DEVOPS_EXT_PAT belongs to from {url} failed: {e}") from e


def ado_threads(repo: dict, pr_id: int) -> list[dict]:
    ado = repo["config"]["azure_devops"]
    result = az("devops", "invoke", *ado_args(repo), "--area", "git", "--resource", "pullRequestThreads",
                "--route-parameters", f"project={ado['project']}", f"repositoryId={ado['repository']}", f"pullRequestId={pr_id}",
                "--api-version", ADO_API)
    comments = []
    for thread in (result or {}).get("value", []):
        for comment in thread.get("comments", []):
            if comment.get("commentType") != "text" or comment.get("isDeleted"):
                continue
            author = comment.get("author", {})
            comments.append({"author": author.get("uniqueName") or author.get("displayName", ""),
                             # the repos are private: every person who can comment works there
                             "trusted": not author.get("isContainer", False),
                             "body": comment.get("content", ""), "at": comment.get("publishedDate", ""), "url": ""})
    return comments


def ado_prs(repo: dict, branches: list[str]) -> list[dict]:
    ado = repo["config"]["azure_devops"]
    prs = []
    for branch in branches:
        found = az("repos", "pr", "list", *ado_args(repo), "--project", ado["project"], "--repository", ado["repository"],
                   "--source-branch", branch, "--status", "all") or []
        for pr in found:
            web = pr.get("repository", {}).get("webUrl", "")
            prs.append({"repo": repo["name"], "host": "azure-devops", "id": pr["pullRequestId"],
                        "url": f"{web}/pullrequest/{pr['pullRequestId']}" if web else "", "branch": branch,
                        "title": pr.get("title", ""), "draft": pr.get("isDraft", False),
                        "head": pr.get("lastMergeSourceCommit", {}).get("commitId"),
                        "base": pr.get("targetRefName", "").removeprefix("refs/heads/"),
                        "state": {"active": "open", "completed": "merged"}.get(pr.get("status"), "closed"),
                        "progress": pr_progress(ado_threads(repo, pr["pullRequestId"]))})
    return prs


def ado_repo_for_ticket(all_repos: dict[str, dict]) -> dict:
    internal = [r for r in all_repos.values() if r["host"] == "azure-devops"]
    if not internal:
        raise FactoryError(f"no internal repo has a {CONFIG}, so there is no Azure DevOps tracker to read")
    return internal[0]


def ado_ticket(repo: dict, number: int) -> dict:
    item = az("boards", "work-item", "show", "--id", str(number), *ado_args(repo))
    fields = item.get("fields", {})
    assigned = fields.get("System.AssignedTo") or {}
    tags = [t.strip() for t in (fields.get("System.Tags") or "").split(";") if t.strip()]
    state = fields.get("System.State", "")
    return {"ref": f"ado:{number}", "title": fields.get("System.Title", ""), "url": item.get("_links", {}).get("html", {}).get("href", ""),
            "body": fields.get("System.Description", ""), "closed": state in ADO_CLOSED_STATES,
            "labels": tags, "assignees": [assigned.get("uniqueName")] if assigned.get("uniqueName") else []}


def ado_comments(repo: dict, number: int) -> list[dict]:
    """A work item's discussion. az boards work-item show has only the latest comment, in System.History."""
    ado = repo["config"]["azure_devops"]
    comments, token = [], None
    while True:
        page = az("devops", "invoke", *ado_args(repo), "--area", "wit", "--resource", "comments",
                  "--route-parameters", f"project={ado['project']}", f"workItemId={number}",
                  "--query-parameters", "order=asc", *([f"continuationToken={token}"] if token else []),
                  "--api-version", ADO_COMMENTS_API) or {}
        for comment in page.get("comments", []):
            author = comment.get("createdBy", {})
            comments.append({"author": author.get("uniqueName") or author.get("displayName", ""),
                             # the same rule as a PR thread: every person who can comment works there
                             "trusted": not author.get("isContainer", False),
                             "body": comment.get("text", ""), "at": comment.get("createdDate", ""), "url": ""})
        # a token that does not move would page forever
        if not page.get("comments") or page.get("continuationToken") in (None, token):
            return comments
        token = page["continuationToken"]


def ado_set_tags(repo: dict, number: int, add: set[str], remove: set[str], assign: str | None = None, unassign: bool = False) -> None:
    current = set(ado_ticket(repo, number)["labels"])
    tags = "; ".join(sorted((current | add) - remove))
    args = ["boards", "work-item", "update", "--id", str(number), *ado_args(repo), "--fields", f"System.Tags={tags}"]
    if assign:
        args += ["--assigned-to", assign]
    elif unassign:
        args += ["--assigned-to", ""]
    az(*args)


def ado_comment_pr(repo: dict, pr_id: int, body: str) -> None:
    ado = repo["config"]["azure_devops"]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fp:
        json.dump({"comments": [{"parentCommentId": 0, "content": body, "commentType": 1}], "status": 1}, fp)
    try:
        az("devops", "invoke", *ado_args(repo), "--area", "git", "--resource", "pullRequestThreads",
           "--route-parameters", f"project={ado['project']}", f"repositoryId={ado['repository']}", f"pullRequestId={pr_id}",
           "--http-method", "POST", "--in-file", fp.name, "--api-version", ADO_API)
    finally:
        os.unlink(fp.name)


def ado_comment_ticket(repo: dict, number: int, body: str) -> None:
    az("boards", "work-item", "update", "--id", str(number), *ado_args(repo), "--discussion", body)


# ---------------------------------------------------------------- state

class Context:
    def __init__(self):
        self.main = main_checkout()
        self.repos = repos(self.main)
        self._slug = None

    @property
    def slug(self) -> str:
        if self._slug is None:
            self._slug = github_slug(self.main)
        return self._slug

    def me(self, ticket: dict) -> str:
        return gh_me(self.main) if ticket["kind"] == "github" else ado_me(ado_repo_for_ticket(self.repos))

    def ticket(self, ticket: dict) -> dict:
        if ticket["kind"] == "github":
            return gh_ticket(self.main, self.slug, ticket["id"])
        return ado_ticket(ado_repo_for_ticket(self.repos), ticket["id"])

    def read(self, ref: str) -> dict:
        """The ticket, its description, and its comments by maintainers, the factory's own marked with their kind."""
        ticket = parse_ticket(ref)
        if ticket["kind"] == "github":
            raw = gh_comments(self.main, self.slug, ticket["id"], include_pr=False)
        else:
            raw = ado_comments(ado_repo_for_ticket(self.repos), ticket["id"])
        comments = [{"author": c["author"], "at": c["at"], "url": c["url"], "role": c["role"], "kind": c["kind"], "body": c["body"]}
                    for c in classify(raw) if c["role"] != "ignored"]
        return {**self.ticket(ticket), "comments": comments}

    def state(self, ref: str) -> dict:
        ticket = parse_ticket(ref)
        info = self.ticket(ticket)
        branches = {name: remote_branches(repo["path"], ticket["prefix"]) for name, repo in self.repos.items()}
        prs = []
        for name, found in branches.items():
            if not found:
                continue
            repo = self.repos[name]
            prs += gh_prs(self.main, self.slug, found) if repo["host"] == "github" else ado_prs(repo, found)
        me = self.me(ticket)
        step = ticket_step(info, prs, branches, me)
        return {"ticket": {**ticket, **{k: v for k, v in info.items() if k != "body"}}, "me": me,
                "branches": {k: v for k, v in branches.items() if v}, "prs": prs, **step}


# ---------------------------------------------------------------- publishing

def check_public(main: str, text: str, required: list[str]) -> None:
    terms = public_text.load_terms(main, required)
    hits = public_text.scan(terms, text, "text")
    if hits:
        raise FactoryError("refusing to publish: " + "; ".join(f"line {h['line']} matches {h['repo']}'s denylist ({h['reason']})" for h in hits))


def check_public_range(main: str, repo_path: str, range_: str, branch: str, required: list[str]) -> None:
    terms = public_text.load_terms(main, required)
    hits = public_text.scan_range(terms, repo_path, range_, branch)
    if hits:
        raise FactoryError("refusing to push: " + "; ".join(f"{h['source']}:{h['line']} matches {h['repo']}'s denylist ({h['reason']})" for h in hits))


def required_denylists(ctx: Context) -> list[str]:
    return [name for name, repo in ctx.repos.items() if repo["host"] == "azure-devops"]


def publish_text(ctx: Context, repo: dict, text: str) -> None:
    if repo["public"]:
        try:
            check_public(ctx.main, text, required_denylists(ctx))
        except public_text.CheckError as e:
            raise FactoryError(f"refusing to publish: {e}") from e


def read_body(path: str) -> str:
    with open(path, encoding="utf-8") as fp:
        return fp.read().strip()


def find_pr(ctx: Context, ref: str, repo_name: str, state: dict | None = None) -> dict:
    state = state or ctx.state(ref)
    found = [pr for pr in state["prs"] if pr["repo"] == repo_name and pr["state"] == "open"]
    if not found:
        raise FactoryError(f"{ref} has no open {repo_name} PR")
    return found[0]


def post_comment(ctx: Context, ref: str, kind: str, body: str, repo_name: str | None) -> dict:
    ticket = parse_ticket(ref)
    full = f"{body}\n\n{marker(kind, {'ticket': ticket['ref']})}" if kind != "review" else body
    if repo_name:
        repo = ctx.repos[repo_name]
        pr = find_pr(ctx, ref, repo_name)
        publish_text(ctx, repo, full)
        if repo["host"] == "github":
            gh(ctx.main, "pr", "comment", str(pr["id"]), "--repo", ctx.slug, "--body-file", "-", stdin=full)
        else:
            ado_comment_pr(repo, pr["id"], full)
        return {"posted": "pr", "repo": repo_name, "pr": pr["url"]}
    if ticket["kind"] == "github":
        publish_text(ctx, ctx.repos[CORE], full)
        gh(ctx.main, "issue", "comment", str(ticket["id"]), "--repo", ctx.slug, "--body-file", "-", stdin=full)
    else:
        ado_comment_ticket(ado_repo_for_ticket(ctx.repos), ticket["id"], full)
    return {"posted": "ticket", "ticket": ticket["ref"]}


# ---------------------------------------------------------------- worktrees

def dev_mounts(main: str) -> list[tuple[str, str]] | None:
    """The dev container's bind mounts as (host, container) pairs, or None without a container."""
    try:
        container = run(["bash", os.path.join(main, "bin", "get-dev-container.sh")], cwd=main).strip()
        out = run(["docker", "inspect", "--format",
                   '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}{{"\\t"}}{{.Destination}}{{"\\n"}}{{end}}{{end}}', container])
    except FactoryError:
        # no dev container is an answer here: the worktree root falls back, and doctor reports it
        return None
    return [tuple(line.split("\t", 1)) for line in out.splitlines() if "\t" in line]


def in_container(path: str, mounts: list[tuple[str, str]]) -> str | None:
    """Where the dev container sees a host path, the deepest mount winning."""
    best = None
    for source, destination in mounts:
        if path == source or path.startswith(source.rstrip("/") + "/"):
            if best is None or len(source) > len(best[0]):
                best = (source, destination)
    return best[1] + path[len(best[0]):] if best else None


def on_host(path: str, mounts: list[tuple[str, str]]) -> str | None:
    best = None
    for source, destination in mounts:
        if path == destination or path.startswith(destination.rstrip("/") + "/"):
            if best is None or len(destination) > len(best[1]):
                best = (source, destination)
    return best[0] + path[len(best[1]):] if best else None


def worktree_root(main: str, mounts: list[tuple[str, str]] | None, env: dict | None = None, home: str | None = None) -> tuple[str, str]:
    env = os.environ if env is None else env
    if env.get("FACTORY_WORKTREE_ROOT"):
        return os.path.abspath(os.path.expanduser(env["FACTORY_WORKTREE_ROOT"])), "FACTORY_WORKTREE_ROOT"
    t3 = os.path.join(home or os.path.expanduser("~"), ".t3", "worktrees", os.path.basename(main))
    if mounts and in_container(t3, mounts):
        return t3, "T3 Code's worktree directory, which the dev container mounts"
    return os.path.join(main, ".claude", "worktrees"), "the main checkout's .claude/worktrees"


def worktree_name(ticket: dict) -> str:
    return "factory-" + ticket["ref"].replace(":", "-")


def find_worktree(main: str, name: str) -> str | None:
    for line in git(main, "worktree", "list", "--porcelain").splitlines():
        if line.startswith("worktree ") and os.path.basename(line[9:]) == name:
            return line[9:]
    return None


def checkout_branch(repo_path: str, branch: str, base: str) -> str:
    """Put repo_path (a worktree) on branch: the pushed one if it exists, else a new one off origin/base."""
    # a worktree already on the branch may hold commits a run has not pushed yet
    if git(repo_path, "rev-parse", "--abbrev-ref", "HEAD").strip() == branch:
        return "existing"
    git(repo_path, "fetch", "--quiet", "origin", base)
    if git(repo_path, "ls-remote", "--heads", "origin", branch).strip():
        git(repo_path, "fetch", "--quiet", "origin", f"{branch}:refs/remotes/origin/{branch}")
        git(repo_path, "switch", "--quiet", "-C", branch, f"origin/{branch}")
        return "resumed"
    # -C: a local branch left by a removed worktree held nothing unpushed (remove_worktree checks)
    git(repo_path, "switch", "--quiet", "-C", branch, f"origin/{base}")
    return "created"


def create_worktree(ctx: Context, ref: str, slug: str | None, internal: list[str]) -> dict:
    ticket = parse_ticket(ref)
    state = ctx.state(ref)
    branches = [b for found in state["branches"].values() for b in found]
    branch = branches[0] if branches else f"{ticket['prefix']}{slugify(slug or state['ticket']['title'])}"
    mounts = dev_mounts(ctx.main)
    root, why = worktree_root(ctx.main, mounts)
    name = worktree_name(ticket)
    path = find_worktree(ctx.main, name)
    created = path is None
    if created:
        path = os.path.join(root, name)
        os.makedirs(root, exist_ok=True)
        git(ctx.main, "fetch", "--quiet", "origin", base_branch(ctx.main))
        git(ctx.main, "worktree", "add", "--quiet", "--detach", path, f"origin/{base_branch(ctx.main)}")
        run(["bash", os.path.join(path, "bin", "setup-worktree.sh")], cwd=path, stdin="", timeout=600)
    result = {"path": path, "root_from": why, "created": created, "branch": branch, "repos": {}}
    # an ado ticket's ace3 side stays detached unless it already has a branch
    if ticket["kind"] == "github" or state["branches"].get(CORE):
        result["repos"][CORE] = checkout_branch(path, branch, base_branch(ctx.main))
    for name in internal:
        if name not in ctx.repos or ctx.repos[name]["host"] != "azure-devops":
            raise FactoryError(f"{name} is not an internal repo with a {CONFIG}")
        repo_path = internal_path(path, name)
        if not os.path.isdir(repo_path):
            # setup-worktree.sh makes the integrations; signatures is made here, from the main checkout's repo
            git(ctx.repos[name]["path"], "worktree", "add", "--quiet", "--detach", repo_path)
        result["repos"][name] = checkout_branch(repo_path, branch, base_branch(ctx.repos[name]["path"]))
    result["container_path"] = in_container(path, mounts) if mounts else None
    return result


def internal_path(worktree: str, name: str) -> str:
    return os.path.join(worktree, "signatures") if name == "signatures" else os.path.join(worktree, "integrations", name)


def repo_path_in(worktree: str, name: str) -> str:
    return worktree if name == CORE else internal_path(worktree, name)


def unpushed(repo_path: str) -> list[str]:
    problems = []
    # new files count: worktree removal is forced, so a file never committed would be lost
    if git(repo_path, "status", "--porcelain").strip():
        problems.append(f"{repo_path} has uncommitted changes")
    branch = git(repo_path, "rev-parse", "--abbrev-ref", "HEAD").strip()
    if branch.startswith("factory/"):
        remote = git(repo_path, "rev-parse", "--verify", "--quiet", f"origin/{branch}", check=False).strip()
        head = git(repo_path, "rev-parse", "HEAD").strip()
        if remote != head:
            problems.append(f"{repo_path}: {branch} is not pushed at {head[:12]}")
    return problems


def remove_worktree(ctx: Context, ref: str) -> dict:
    ticket = parse_ticket(ref)
    path = find_worktree(ctx.main, worktree_name(ticket))
    if not path:
        return {"removed": False, "why": "no worktree"}
    problems = []
    for name in ctx.repos:
        repo_path = repo_path_in(path, name)
        if os.path.isdir(repo_path) and os.path.exists(os.path.join(repo_path, ".git")):
            problems += unpushed(repo_path)
    if problems:
        raise FactoryError("not removing the worktree: " + "; ".join(problems))
    for name, repo in ctx.repos.items():
        if name != CORE and os.path.isdir(internal_path(path, name)):
            git(repo["path"], "worktree", "remove", "--force", internal_path(path, name), check=False)
    git(ctx.main, "worktree", "remove", "--force", path)
    return {"removed": True, "path": path}


# ---------------------------------------------------------------- pushing and PRs

def base_check(repo_path: str, head: str, base: str) -> dict:
    """Whether the base moved under the patch: files both sides changed, or a merge that conflicts.

    A rebase restarts the review from scratch (ace-review runs a full round when the merge-base
    moves), so the branch is rebased only when the base's changes can affect the patch."""
    git(repo_path, "fetch", "--quiet", "origin", base)
    upstream = f"origin/{base}"
    merge_base = git(repo_path, "merge-base", head, upstream).strip()
    ours = set(git(repo_path, "diff", "--name-only", merge_base, head).split())
    theirs = set(git(repo_path, "diff", "--name-only", merge_base, upstream).split())
    behind = int(git(repo_path, "rev-list", "--count", f"{head}..{upstream}").strip())
    merge = subprocess.run(["git", "-C", repo_path, "merge-tree", "--write-tree", "--name-only", "--no-messages", upstream, head],
                           capture_output=True, text=True, timeout=TIMEOUT)
    if merge.returncode not in (0, 1):
        raise FactoryError(f"git merge-tree failed: {merge.stderr.strip()}")
    conflicts = merge.stdout.splitlines()[1:] if merge.returncode == 1 else []
    overlap = sorted(ours & theirs)
    return {"behind": behind, "overlap": overlap, "conflicts": conflicts, "rebase": bool(overlap or conflicts)}


def ticket_base_check(ctx: Context, ref: str, repo_name: str) -> dict:
    ticket = parse_ticket(ref)
    repo = ctx.repos[repo_name]
    worktree = find_worktree(ctx.main, worktree_name(ticket))
    if worktree and os.path.isdir(repo_path_in(worktree, repo_name)):
        path, head = repo_path_in(worktree, repo_name), "HEAD"
    else:
        branch = (remote_branches(repo["path"], ticket["prefix"]) or [None])[0]
        if not branch:
            raise FactoryError(f"{ref} has no {repo_name} branch")
        git(repo["path"], "fetch", "--quiet", "origin", f"{branch}:refs/remotes/origin/{branch}")
        path, head = repo["path"], f"origin/{branch}"
    return {"repo": repo_name, **base_check(path, head, base_branch(repo["path"]))}


CHECK_TIMEOUT = 1800


def changed_files(repo_path: str, base: str) -> list[str]:
    """What the branch changes against the base, committed or not, new files included."""
    merge_base = git(repo_path, "merge-base", "HEAD", f"origin/{base}").strip()
    changed = set(git(repo_path, "diff", "--name-only", "--diff-filter=d", merge_base).split())
    changed |= set(git(repo_path, "ls-files", "--others", "--exclude-standard").split())
    return sorted(changed)


def check_commands(checks: list[dict], changed: list[str]) -> list[dict]:
    """Each check's command, with {changed} filled in by the changed files its paths match. A
    check with paths that match nothing is skipped."""
    planned = []
    for check in checks:
        files = [f for f in changed if any(fnmatch.fnmatch(f, p) for p in check["paths"])] if check.get("paths") else changed
        if check.get("paths") and not files:
            planned.append({"name": check["name"], "skipped": "it changes none of " + ", ".join(check["paths"])})
            continue
        planned.append({"name": check["name"], "command": check["command"].replace("{changed}", " ".join(shlex.quote(f) for f in files))})
    return planned


def run_checks(ctx: Context, ref: str, repo_name: str) -> dict:
    repo = ctx.repos.get(repo_name)
    if not repo or repo["host"] != "azure-devops":
        raise FactoryError(f"{repo_name} is not an internal repo with a {CONFIG}")
    worktree = find_worktree(ctx.main, worktree_name(parse_ticket(ref)))
    if not worktree:
        raise FactoryError(f"{ref} has no worktree")
    path = repo_path_in(worktree, repo_name)
    git(path, "fetch", "--quiet", "origin", base_branch(repo["path"]))
    results = []
    for check in check_commands(repo["config"].get("check", []), changed_files(path, base_branch(repo["path"]))):
        if "skipped" in check:
            results.append(check)
            continue
        # in dev, from the repo's root, where the checks' dependencies are installed
        cmd = ["bash", os.path.join(worktree, "bin", "exec-in-container.sh"), "bash", "-c",
               f"cd {shlex.quote(os.path.relpath(path, worktree))} && {check['command']}"]
        try:
            result = subprocess.run(cmd, cwd=worktree, capture_output=True, text=True, timeout=CHECK_TIMEOUT)
            results.append({**check, "exit": result.returncode, "output": (result.stdout + result.stderr)[-4000:]})
        except subprocess.TimeoutExpired:
            results.append({**check, "exit": None, "output": f"timed out after {CHECK_TIMEOUT}s"})
    return {"ok": all(r.get("exit", 0) == 0 for r in results), "checks": results}


def push(ctx: Context, ref: str, repo_name: str) -> dict:
    ticket = parse_ticket(ref)
    worktree = find_worktree(ctx.main, worktree_name(ticket))
    if not worktree:
        raise FactoryError(f"{ref} has no worktree")
    repo = ctx.repos[repo_name]
    path = repo_path_in(worktree, repo_name)
    branch = git(path, "rev-parse", "--abbrev-ref", "HEAD").strip()
    if not branch.startswith(ticket["prefix"]):
        raise FactoryError(f"{path} is on {branch}, not a {ticket['prefix']}* branch")
    base = base_branch(repo["path"])
    git(path, "fetch", "--quiet", "origin", base)
    if repo["public"]:
        try:
            check_public_range(ctx.main, path, f"origin/{base}..HEAD", branch, required_denylists(ctx))
        except public_text.CheckError as e:
            raise FactoryError(f"refusing to push: {e}") from e
    git(path, "push", "--quiet", "--force-with-lease", "-u", "origin", f"HEAD:refs/heads/{branch}")
    return {"pushed": branch, "repo": repo_name, "head": git(path, "rev-parse", "HEAD").strip()}


def closing(ticket: dict, body: str) -> str:
    """The body with a line that closes the GitHub ticket when the PR merges, unless it has one."""
    if ticket["kind"] != "github" or re.search(rf"\b(fix(e[sd])?|close[sd]?|resolve[sd]?) #{ticket['id']}\b", body, re.IGNORECASE):
        return body
    return f"{body}\n\nFixes #{ticket['id']}"


def check_ado_description(body: str) -> None:
    if len(body) > ADO_DESCRIPTION_LIMIT:
        raise FactoryError(f"the description is {len(body)} characters; Azure DevOps takes {ADO_DESCRIPTION_LIMIT}")


def pr_create(ctx: Context, ref: str, repo_name: str, title: str, body: str) -> dict:
    ticket = parse_ticket(ref)
    state = ctx.state(ref)
    branch = (state["branches"].get(repo_name) or [None])[0]
    if not branch:
        raise FactoryError(f"push {repo_name}'s branch before opening its PR")
    if any(pr["repo"] == repo_name and pr["state"] == "open" for pr in state["prs"]):
        raise FactoryError(f"{ref} already has an open {repo_name} PR")
    repo = ctx.repos[repo_name]
    if repo["public"]:
        body = closing(ticket, body)
        publish_text(ctx, repo, f"{title}\n{body}")
        url = gh(ctx.main, "pr", "create", "--repo", ctx.slug, "--draft", "--head", branch, "--base", base_branch(ctx.main),
                 "--title", title, "--body-file", "-", stdin=body).strip()
        return {"pr": url}
    check_ado_description(body)
    ado = repo["config"]["azure_devops"]
    pr = az("repos", "pr", "create", *ado_args(repo), "--project", ado["project"], "--repository", ado["repository"],
            "--source-branch", branch, "--target-branch", base_branch(repo["path"]), "--title", title,
            "--description", body, "--draft", "true")
    if ticket["kind"] == "ado":
        az("repos", "pr", "work-item", "add", *ado_args(repo), "--id", str(pr["pullRequestId"]), "--work-items", str(ticket["id"]))
    return {"pr": f"{pr.get('repository', {}).get('webUrl', '')}/pullrequest/{pr['pullRequestId']}"}


def pr_body(ctx: Context, ref: str, repo_name: str, body: str) -> dict:
    repo = ctx.repos[repo_name]
    pr = find_pr(ctx, ref, repo_name)
    if repo["public"]:
        body = closing(parse_ticket(ref), body)
        publish_text(ctx, repo, body)
        gh(ctx.main, "pr", "edit", str(pr["id"]), "--repo", ctx.slug, "--body-file", "-", stdin=body)
    else:
        check_ado_description(body)
        az("repos", "pr", "update", "--id", str(pr["id"]), *ado_args(repo), "--description", body)
    return {"updated": pr["url"]}


def ado_pr_labels(repo: dict, pr_id: int, method: str = "GET", name: str | None = None) -> list[str]:
    ado = repo["config"]["azure_devops"]
    route = ["--route-parameters", f"project={ado['project']}", f"repositoryId={ado['repository']}", f"pullRequestId={pr_id}"]
    if method == "DELETE":
        route.append(f"labelIdOrName={name}")
    args = ["devops", "invoke", *ado_args(repo), "--area", "git", "--resource", "pullRequestLabels", *route,
            "--http-method", method, "--api-version", ADO_API]
    if method != "POST":
        result = az(*args)
        return [l["name"] for l in (result or {}).get("value", [])]
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fp:
        json.dump({"name": name}, fp)
    try:
        az(*args, "--in-file", fp.name)
    finally:
        os.unlink(fp.name)
    return []


def pr_labels(ctx: Context, ref: str, repo_name: str, add: list[str], remove: list[str]) -> dict:
    """Label a factory PR. On GitHub only labels the repo already has, so a typo never makes a new
    one; never a factory:* label, which is the ticket's state, not the change's."""
    repo = ctx.repos[repo_name]
    pr = find_pr(ctx, ref, repo_name)
    if bad := sorted(l for l in add + remove if l in LABELS):
        raise FactoryError(f"{', '.join(bad)} label the ticket's state, not a PR")
    if repo["host"] == "github":
        existing = label_names(ctx)
        if unknown := sorted(set(add) - existing):
            raise FactoryError(f"the repo has no label {', '.join(unknown)}; pick from: {', '.join(sorted(existing - set(LABELS)))}")
        if add or remove:
            args = ["pr", "edit", str(pr["id"]), "--repo", ctx.slug]
            for label in add:
                args += ["--add-label", label]
            for label in remove:
                args += ["--remove-label", label]
            gh(ctx.main, *args)
        labels = json.loads(gh(ctx.main, "pr", "view", str(pr["id"]), "--repo", ctx.slug, "--json", "labels"))["labels"]
        return {"pr": pr["url"], "labels": sorted(l["name"] for l in labels), "available": sorted(existing - set(LABELS))}
    for label in add:
        ado_pr_labels(repo, pr["id"], "POST", label)
    for label in remove:
        ado_pr_labels(repo, pr["id"], "DELETE", label)
    return {"pr": pr["url"], "labels": sorted(ado_pr_labels(repo, pr["id"]))}


def host_bundle(ctx: Context, bundle: str) -> str:
    """A review bundle's path on the host, given its path on either side."""
    if not os.path.isdir(bundle):
        bundle = on_host(bundle, dev_mounts(ctx.main) or []) or bundle
    return bundle


def post_review(ctx: Context, ref: str, repo_name: str, bundle: str) -> dict:
    """Post an ace-review round as one comment: its report, and a marker carrying its result."""
    bundle = host_bundle(ctx, bundle)
    with open(os.path.join(bundle, "factory.json")) as fp:
        result = json.load(fp)
    report = read_body(os.path.join(bundle, "report.md"))
    # the bundle's path is local to this machine
    report = re.sub(r"\s*Bundle: [^<\n]*", "", report)
    pr = find_pr(ctx, ref, repo_name)
    if result.get("head") != pr["head"]:
        raise FactoryError(f"the review is of {str(result.get('head'))[:12]}, but the PR's head is {str(pr['head'])[:12]}; push, then review again")
    data = {key: result[key] for key in ("round", "head", "verdict", "open", "bundle")}
    if result.get("held"):
        data["held"] = result["held"]
    body = f"{report}\n\n{marker('review', {**data, 'ticket': parse_ticket(ref)['ref']})}"
    posted = post_comment(ctx, ref, "review", body, repo_name)
    return {**posted, "verdict": result["verdict"], "round": result["round"]}


def promote(ctx: Context, ref: str) -> dict:
    state = ctx.state(ref)
    if state["next"] != "promote":
        raise FactoryError(f"{ref} is not ready to promote: {state['why']}")
    done = []
    for pr in state["prs"]:
        if pr["state"] != "open" or not pr["draft"]:
            continue
        repo = ctx.repos[pr["repo"]]
        if repo["host"] == "github":
            gh(ctx.main, "pr", "ready", str(pr["id"]), "--repo", ctx.slug)
        else:
            az("repos", "pr", "update", "--id", str(pr["id"]), *ado_args(repo), "--draft", "false")
        done.append(pr["url"])
    set_labels(ctx, ref, add=set(), remove={IN_PROGRESS, READY})
    return {"ready": done}


# ---------------------------------------------------------------- labels and claiming

def set_labels(ctx: Context, ref: str, add: set[str], remove: set[str], assign: bool = False, unassign: bool = False) -> None:
    ticket = parse_ticket(ref)
    if ticket["kind"] == "github":
        args = ["issue", "edit", str(ticket["id"]), "--repo", ctx.slug]
        for label in sorted(add):
            args += ["--add-label", label]
        for label in sorted(remove):
            args += ["--remove-label", label]
        if assign:
            args += ["--add-assignee", "@me"]
        if unassign:
            args += ["--remove-assignee", "@me"]
        gh(ctx.main, *args)
    else:
        repo = ado_repo_for_ticket(ctx.repos)
        ado_set_tags(repo, ticket["id"], add, remove, assign=ado_me(repo) if assign else None, unassign=unassign)


def claim(ctx: Context, ref: str) -> dict:
    state = ctx.state(ref)
    if state["next"] in ("blocked", "not-ready", "done", "needs-info", "needs-human"):
        raise FactoryError(f"cannot claim {ref}: {state['why']}")
    set_labels(ctx, ref, add={IN_PROGRESS}, remove={READY, NEEDS_INFO}, assign=True)
    return {"claimed": ref, "by": state["me"], "next": state["next"]}


def release(ctx: Context, ref: str, to: str, body: str | None, repo_name: str | None = None) -> dict:
    label = STOP_LABELS[to]
    if body:
        state = ctx.state(ref)
        open_repos = [pr["repo"] for pr in state["prs"] if pr["state"] == "open"]
        # a question about the ticket goes on the ticket; a stop goes on the PR that stopped, since
        # that PR's round count starts again from it: the repo given, or the one the state names
        target = None
        if to == "needs-human" and open_repos:
            target = next((r for r in (repo_name, state.get("repo")) if r in open_repos), open_repos[0])
        post_comment(ctx, ref, "question" if to == "needs-info" else "stop" if to == "needs-human" else "note", body, target)
    set_labels(ctx, ref, add={label}, remove=set(STOP_LABELS.values()) - {label} | {IN_PROGRESS},
               unassign=to in ("needs-info", "ready"))
    return {"released": ref, "to": label}


def label_names(ctx: Context) -> set[str]:
    return {l["name"] for l in json.loads(gh(ctx.main, "label", "list", "--repo", ctx.slug, "--limit", "500", "--json", "name"))}


def ensure_labels(ctx: Context) -> dict:
    existing = label_names(ctx)
    made = []
    for name, (color, description) in LABELS.items():
        if name not in existing:
            gh(ctx.main, "label", "create", name, "--repo", ctx.slug, "--color", color, "--description", description)
            made.append(name)
    return {"created": made, "existing": sorted(set(LABELS) & existing)}


def ready(ctx: Context) -> dict:
    issues = json.loads(gh(ctx.main, "issue", "list", "--repo", ctx.slug, "--label", READY, "--state", "open",
                           "--json", "number,title,labels,assignees,url", "--limit", "100"))
    tickets = [{"ticket": str(i["number"]), "title": i["title"], "url": i["url"],
                "assignees": [a["login"] for a in i["assignees"]]} for i in issues]
    for repo in ctx.repos.values():
        if repo["host"] != "azure-devops":
            continue
        ado = repo["config"]["azure_devops"]
        wiql = (f"SELECT [System.Id], [System.Title] FROM workitems WHERE [System.TeamProject] = '{ado['project']}' "
                f"AND [System.Tags] CONTAINS '{READY}' AND [System.State] NOT IN ({', '.join(repr(s) for s in ADO_CLOSED_STATES)})")
        for item in az("boards", "query", *ado_args(repo), "--project", ado["project"], "--wiql", wiql) or []:
            tickets.append({"ticket": f"ado:{item['id']}", "title": item.get("fields", {}).get("System.Title", ""), "url": "", "assignees": []})
        break  # one Azure DevOps project holds the work items of every internal repo
    return {"ready": tickets}


# ---------------------------------------------------------------- retro

def retro_state_path(main: str) -> str:
    return os.path.join(main, "local", "factory", "retro.json")


def issue_create(ctx: Context, title: str, body: str, labels: list[str]) -> dict:
    publish_text(ctx, ctx.repos[CORE], f"{title}\n{body}")
    args = ["issue", "create", "--repo", ctx.slug, "--title", title, "--body-file", "-"]
    for label in labels:
        args += ["--label", label]
    return {"issue": gh(ctx.main, *args, stdin=body).strip()}


# ---------------------------------------------------------------- backlog

FLAW_LABEL = "design flaw"
# a pre-existing finding's ace3 label: the dimension's own where the repo has one, else bug
DIMENSION_LABELS = {"logging": "logging", "performance": "performance", "tests": "tests"}
BACKLOG_TAG = "factory:backlog"
SIMILAR_LIMIT = 15


def load_bundle_json(bundle: str, name: str, default=None):
    try:
        with open(os.path.join(bundle, name)) as fp:
            return json.load(fp)
    except FileNotFoundError:
        return default


def dump_bundle_json(bundle: str, name: str, data) -> None:
    with open(os.path.join(bundle, name), "w") as fp:
        json.dump(data, fp, indent=2)


def backlog_candidates(bundle: str) -> list[dict]:
    """What a finished round leaves for the backlog: its pre-existing findings, and the design flaws
    no issue had yet."""
    summary = load_bundle_json(bundle, "summary.json")
    if summary is None:
        raise FactoryError(f"{bundle} is not finished: run findings.py finish first")
    flaws = {f["fid"]: f for f in load_bundle_json(bundle, "flaws.json", [])}
    keys = ("title", "file", "line", "dimension", "severity", "evidence", "impact", "fix", "risks")
    found = [{"id": f["id"], "kind": "finding", **{k: f.get(k) for k in keys}}
             for f in load_bundle_json(bundle, "verified.json", []) if f.get("origin") == "pre-existing"]
    keys = ("title", "file", "line", "area", "flaw", "workaround", "fix_size", "fix", "risks")
    found += [{"id": s["id"], "kind": "flaw", **{k: flaws[s["id"]].get(k) for k in keys}}
              for s in summary.get("flaws", []) if s.get("new") and s["id"] in flaws]
    return found


def backlog_trackers(ctx: Context, repo_name: str, candidate: dict) -> list[str]:
    """The repos whose tracker may hold the candidate. A pre-existing finding stays with the code it
    is in. A flaw found reviewing ace3 is in public code, so ace3's. A flaw found reviewing an
    internal repo is ace3's when it is in core, which the change only works around, and the internal
    repo's when it is in that repo's own code; only the driver, reading it, can tell which."""
    if candidate["kind"] == "finding" or ctx.repos[repo_name]["public"]:
        return [repo_name if candidate["kind"] == "finding" else CORE]
    return [CORE, repo_name]


def backlog_home(ctx: Context, repo_name: str, candidate: dict, decision: dict) -> dict:
    trackers = backlog_trackers(ctx, repo_name, candidate)
    if len(trackers) == 1:
        return ctx.repos[trackers[0]]
    if decision.get("tracker") not in trackers:
        raise FactoryError(f"{candidate['id']} is a design flaw found in {repo_name}: its decision names its tracker, "
                           f"{CORE} (a flaw in core) or {repo_name} (one in {repo_name}'s own code)")
    return ctx.repos[decision["tracker"]]


def similar_issues(ctx: Context, repo_name: str, candidate: dict, home: dict) -> list[dict]:
    """Issues or work items in one tracker that may already be this candidate, for the driver to
    judge. A search is not published, but an internal repo's file names stay out of a search of the
    public repo."""
    named = candidate.get("file") and (ctx.repos[repo_name]["public"] or not home["public"])
    term = os.path.basename(candidate["file"]) if named else candidate.get("area") or candidate["title"]
    if home["host"] == "github":
        rows = json.loads(gh(ctx.main, "issue", "list", "--repo", ctx.slug, "--state", "all", "--search", f'"{term}"',
                             "--json", "number,title,state,url", "--limit", str(SIMILAR_LIMIT)) or "[]")
        return [{"ref": f"#{r['number']}", "title": r["title"], "state": r["state"].lower(), "url": r["url"]} for r in rows]
    ado = home["config"]["azure_devops"]
    term = term.replace("'", "''")
    wiql = (f"SELECT [System.Id], [System.Title], [System.State] FROM workitems WHERE [System.TeamProject] = '{ado['project']}' "
            f"AND [System.WorkItemType] = 'Bug' AND ([System.Title] CONTAINS '{term}' OR [System.Description] CONTAINS WORDS '{term}')")
    items = az("boards", "query", *ado_args(home), "--project", ado["project"], "--wiql", wiql) or []
    return [{"ref": f"ado:{i['id']}", "title": i.get("fields", {}).get("System.Title", ""),
             "state": i.get("fields", {}).get("System.State", "")} for i in items[:SIMILAR_LIMIT]]


def backlog(ctx: Context, ref: str, repo_name: str, bundle: str) -> dict:
    bundle = host_bundle(ctx, bundle)
    filed = load_bundle_json(bundle, "filed-backlog.json", {})
    candidates = []
    for c in backlog_candidates(bundle):
        trackers = backlog_trackers(ctx, repo_name, c)
        found = ({"recorded": filed[c["id"]]} if c["id"] in filed
                 else {"similar": {t: similar_issues(ctx, repo_name, c, ctx.repos[t]) for t in trackers}})
        candidates.append({**c, "trackers": trackers, **found})
    return {"candidates": candidates}


def finding_body(candidate: dict, found_in: str) -> str:
    where = f"`{candidate['file']}:{candidate['line']}`" if candidate.get("line") else f"`{candidate['file']}`"
    return (f"{candidate['evidence']}\n\n**Impact:** {candidate['impact']}\n\n**Fix:** {candidate['fix']}\n\n"
            f"{findings.risks_markdown(candidate.get('risks'))}**Where:** {where}\n\n<sub>Found by /ace-review as pre-existing ({candidate['dimension']}, {candidate['severity']}) "
            f"in code {found_in} touches; filed by /factory.</sub>")


def flaw_body(candidate: dict, worked_around: str) -> str:
    return findings.flaw_issue_body(candidate, worked_around, "<sub>Found by /ace-review; filed by /factory.</sub>")


def ado_html(text: str) -> str:
    return "".join(f"<p>{html.escape(p).replace(chr(10), '<br>')}</p>" for p in text.split("\n\n"))


def ado_bug(repo: dict, title: str, body: str, tags: list[str]) -> str:
    ado = repo["config"]["azure_devops"]
    item = az("boards", "work-item", "create", *ado_args(repo), "--project", ado["project"], "--type", "Bug",
              "--title", title, "--description", ado_html(body), "--fields", f"System.Tags={'; '.join([BACKLOG_TAG, *tags])}")
    return item.get("_links", {}).get("html", {}).get("href") or f"ado:{item['id']}"


def file_candidate(ctx: Context, repo_name: str, pr: dict, candidate: dict, decision: dict, home: dict) -> str:
    title = decision.get("title") or candidate["title"]
    reviewed = ctx.repos[repo_name]
    # an internal repo's PR, branch and paths never go in a public issue
    pr_ref = f"#{pr['id']}" if reviewed["public"] else pr["url"] or f"PR {pr['id']}"
    if candidate["kind"] == "flaw":
        where = (f"in {pr_ref}, `{candidate['file']}:{candidate['line']}`" if reviewed["public"] or not home["public"]
                 else "by a change in an internal repository")
        body = decision.get("body") or flaw_body(candidate, where)
        if home["public"]:
            return issue_create(ctx, title, body, [FLAW_LABEL])["issue"]
        return ado_bug(home, title, body, [FLAW_LABEL, home["name"]])
    body = decision.get("body") or finding_body(candidate, pr_ref)
    if home["public"]:
        return issue_create(ctx, title, body, [DIMENSION_LABELS.get(candidate["dimension"], "bug")])["issue"]
    return ado_bug(home, title, body, [home["name"]])


def flaw_record(ctx: Context, home: dict, ref: str) -> dict:
    """findings.py's record of a flaw's issue: an ace3 issue by number, a work item by its link."""
    if not home["public"]:
        return {"id": None, "url": ref}
    match = re.fullmatch(r"#?(\d+)|.*/issues/(\d+)", str(ref).strip())
    if not match:
        raise FactoryError(f"a design flaw kept in {CORE} is an issue of it, not {ref!r}")
    number = int(match.group(1) or match.group(2))
    return {"id": number, "url": f"https://github.com/{ctx.slug}/issues/{number}"}


def file_backlog(ctx: Context, ref: str, repo_name: str, bundle: str) -> dict:
    """File each backlog candidate the driver judged new in $B/backlog.json, and record each one it
    matched to an existing issue. A candidate already recorded is never filed twice. A write the
    public-text check refuses is reported, not fatal: the driver rewrites its title or body there."""
    bundle = host_bundle(ctx, bundle)
    candidates = backlog_candidates(bundle)
    decisions = {d["id"]: d for d in load_bundle_json(bundle, "backlog.json", [])}
    if missing := [c["id"] for c in candidates if c["id"] not in decisions]:
        raise FactoryError(f"backlog.json has no decision for {', '.join(missing)}")
    if unknown := sorted(set(decisions) - {c["id"] for c in candidates}):
        raise FactoryError(f"backlog.json decides {', '.join(unknown)}, which this round does not have")
    # every tracker is settled before anything is written
    homes = {c["id"]: backlog_home(ctx, repo_name, c, decisions[c["id"]]) for c in candidates}
    pr = find_pr(ctx, ref, repo_name)
    filed = load_bundle_json(bundle, "filed-backlog.json", {})
    flaws = load_bundle_json(bundle, "filed-flaws.json", {})
    refused = []
    for candidate in candidates:
        cid, decision = candidate["id"], decisions[candidate["id"]]
        if cid in filed:
            continue
        if decision.get("duplicate"):
            filed[cid] = {"ref": str(decision["duplicate"]), "filed": False}
        else:
            try:
                filed[cid] = {"ref": file_candidate(ctx, repo_name, pr, candidate, decision, homes[cid]), "filed": True}
            except FactoryError as e:
                refused.append({"id": cid, "error": str(e)})
                continue
        if candidate["kind"] == "flaw":
            flaws[cid] = {**flaw_record(ctx, homes[cid], filed[cid]["ref"]), "title": candidate["title"], "status": "open"}
            dump_bundle_json(bundle, "filed-flaws.json", flaws)
        # after each one, so a failure part way through never files the earlier ones again
        dump_bundle_json(bundle, "filed-backlog.json", filed)
    return {"recorded": filed, "refused": refused}


def work_after_ship(repo: str, shipped: str, head: str, merge_commit: str | None) -> str | None:
    """The commits on the branch after its ship head that the base didn't bring in, each with its stat.

    A merge shows only what its author changed beyond git's own merge (conflict resolutions and edits
    made in the merge), so merging the base into the branch doesn't count the base's work as theirs."""
    # the base as it was when the PR merged
    exclude = [f"^{merge_commit}^1"] if merge_commit else []
    try:
        commits = git(repo, "rev-list", "--topo-order", "--reverse", "--parents", head, f"^{shipped}", *exclude).split("\n")
    except FactoryError as e:
        # a ship head that a force-push dropped: say so, rather than report nothing changed
        return f"could not list the commits after ship: {e}"
    shown = []
    for line in filter(None, commits):
        sha, *parents = line.split()
        remerge = ["--remerge-diff"] if len(parents) > 1 else []
        shown.append(git(repo, "show", *remerge, "--stat", "--format=%h %s", sha, check=False).strip())
    return "\n\n".join(shown) or None


def retro_data(ctx: Context, since: str | None, mark: bool) -> dict:
    """The merged ace3 factory PRs since the last retro: their review rounds, the maintainers'
    comments, and what changed after the factory's last ship verdict, which is what a human
    had to do that the factory didn't."""
    path = retro_state_path(ctx.main)
    if since is None and os.path.exists(path):
        with open(path) as fp:
            since = json.load(fp).get("last_merged_at")
    merged = json.loads(gh(ctx.main, "pr", "list", "--repo", ctx.slug, "--state", "merged", "--search", "head:factory/",
                           "--json", "number,title,headRefName,mergedAt,url,headRefOid,mergeCommit", "--limit", "200"))
    prs = []
    for pr in sorted(merged, key=lambda p: p["mergedAt"]):
        if not pr["headRefName"].startswith("factory/") or (since and pr["mergedAt"] <= since):
            continue
        comments = classify(gh_comments(ctx.main, ctx.slug, pr["number"], include_pr=True))
        reviews = [c["data"] for c in comments if c["role"] == "factory" and c["kind"] == "review"]
        ships = [r for r in reviews if r.get("verdict") == "ship"]
        after_ship = None
        if ships and ships[-1].get("head") and ships[-1]["head"] != pr["headRefOid"]:
            merge_commit = (pr.get("mergeCommit") or {}).get("oid")
            git(ctx.main, "fetch", "--quiet", "origin", f"pull/{pr['number']}/head", *([merge_commit] if merge_commit else []))
            after_ship = work_after_ship(ctx.main, ships[-1]["head"], pr["headRefOid"], merge_commit)
        prs.append({"pr": pr["url"], "title": pr["title"], "merged_at": pr["mergedAt"],
                    "rounds": [{"round": r.get("round"), "verdict": r.get("verdict"), "open": r.get("open", [])} for r in reviews],
                    "stops": sum(1 for c in comments if c["role"] == "factory" and c["kind"] == "stop"),
                    "maintainer_comments": [{"author": c["author"], "at": c["at"], "url": c["url"], "body": c["body"]}
                                            for c in comments if c["role"] == "human"],
                    "changed_after_ship": after_ship})
    if mark and prs:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fp:
            json.dump({"last_merged_at": prs[-1]["merged_at"]}, fp)
    return {"since": since, "prs": prs}


# ---------------------------------------------------------------- handoffs

HANDOFF_FIELDS = {"task", "repo", "ticket", "pr_url", "branch", "head_sha", "verdict", "findings_open", "next_state", "stop_reason"}


def handoff_problems(result: dict) -> list[str]:
    problems = []
    missing, extra = HANDOFF_FIELDS - result.keys(), result.keys() - HANDOFF_FIELDS
    if missing:
        problems.append(f"missing {', '.join(sorted(missing))}")
    if extra:
        problems.append(f"unknown {', '.join(sorted(extra))}")
    if missing:
        return problems
    if result["task"] not in TASKS:
        problems.append(f"task is one of {', '.join(TASKS)}")
    if result["next_state"] not in NEXT_STATES:
        problems.append(f"next_state is one of {', '.join(NEXT_STATES)}")
    if result["verdict"] is not None and result["verdict"] not in VERDICTS:
        problems.append(f"verdict is null or one of {', '.join(VERDICTS)}")
    if not isinstance(result["findings_open"], list) or not all(isinstance(f, str) for f in result["findings_open"]):
        problems.append("findings_open is a list of finding ids")
    if result["head_sha"] is not None and not re.fullmatch(r"[0-9a-f]{40}", str(result["head_sha"])):
        problems.append("head_sha is null or a full commit sha")
    try:
        parse_ticket(str(result["ticket"]))
    except FactoryError as e:
        problems.append(str(e))
    stops = result["next_state"] in ("needs-info", "needs-human")
    if stops and not result["stop_reason"]:
        problems.append(f"next_state {result['next_state']} needs a stop_reason")
    if result["next_state"] == "promote" and result["verdict"] != "ship":
        problems.append("next_state promote needs verdict ship")
    if result["task"] == "review" and not stops and result["verdict"] is None:
        problems.append("a review that did not stop has a verdict")
    return problems


def check_handoff(ctx: Context, path: str) -> dict:
    with open(path) as fp:
        result = json.load(fp)
    problems = handoff_problems(result)
    if problems:
        return {"valid": False, "problems": problems}
    state = ctx.state(str(result["ticket"]))
    live = state["next"]
    # the ticket's state is what the next run starts from; a result that disagrees with it is wrong
    if live != result["next_state"]:
        return {"valid": False, "problems": [f"the task says next is {result['next_state']}, but the ticket's state says {live} ({state['why']})"],
                "state_next": live}
    return {"valid": True, "next": live, "why": state["why"]}


# ---------------------------------------------------------------- doctor

def doctor(ctx: Context) -> dict:
    checks = []

    def add(name: str, ok: bool, detail: str, fix: str = "", warning: str = "") -> None:
        checks.append({"check": name, "ok": ok, "detail": detail, **({"fix": fix} if fix and not ok else {}),
                       **({"warning": warning} if warning else {})})

    try:
        add("gh", True, f"logged in as {gh_me(ctx.main)}, repo {ctx.slug}")
    except FactoryError as e:
        add("gh", False, str(e), "gh auth login")
    mounts = dev_mounts(ctx.main)
    add("dev container", mounts is not None, "found" if mounts is not None else "not running",
        "docker compose up -d (from the main checkout)")
    root, why = worktree_root(ctx.main, mounts)
    add("worktree root", True, f"{root} ({why})")
    if mounts is not None:
        seen = in_container(root, mounts)
        add("worktree root in dev", bool(seen), seen or f"{root} is not mounted in dev",
            "mount it for the dev service in the main checkout's docker-compose.override.yml (docs/MULTI_INSTANCE.md)")
        if not root.startswith(ctx.main + "/"):
            git_dir = os.path.join(ctx.main, ".git")
            add("main .git in dev", in_container(git_dir, mounts) == git_dir, "git in dev reads a worktree outside the checkout through the main .git at its host path",
                f"mount ./.git:{git_dir} for dev (docs/MULTI_INSTANCE.md)")
            for name, repo in ctx.repos.items():
                if repo["host"] == "azure-devops":
                    repo_git = os.path.join(repo["path"], ".git")
                    add(f"{name} .git in dev", in_container(repo_git, mounts) == repo_git,
                        f"ace-review runs git in dev on {name}'s worktree, whose .git names {repo_git}",
                        f"mount {os.path.relpath(repo_git, ctx.main)}:{repo_git} for dev")
    for name in public_text.internal_repos(ctx.main):
        has_config = name in ctx.repos
        has_denylist = os.path.exists(os.path.join(public_text.internal_repos(ctx.main)[name], public_text.DENYLIST))
        add(f"{name} factory files", has_config and has_denylist,
            f"config {'found' if has_config else 'missing'}, denylist {'found' if has_denylist else 'missing'}",
            f"commit {CONFIG} and {public_text.DENYLIST} in {name}")
    try:
        terms = public_text.load_terms(ctx.main, required_denylists(ctx))
        if public_text.internal_repos(ctx.main):
            add("denylists", True, f"{len(terms)} terms loaded")
        else:
            add("denylists", True, "no internal repo in the checkout", warning=(
                "no internal repo in this checkout (signatures/ or integrations/<name> as a git repo), so public writes "
                "are checked against no terms: nothing but the No internal detail rule keeps internal names out of ace3"))
    except public_text.CheckError as e:
        add("denylists", False, str(e), "nothing public can be posted until this passes")
    if any(r["host"] == "azure-devops" for r in ctx.repos.values()):
        try:
            add("az", True, f"logged in as {ado_me(ado_repo_for_ticket(ctx.repos))}")
        except FactoryError as e:
            add("az", False, str(e), "az login, or set AZURE_DEVOPS_EXT_PAT to a valid PAT")
    try:
        missing = sorted(set(LABELS) - label_names(ctx))
        add("labels", not missing, f"missing {', '.join(missing)}" if missing else "all present", "factory.py labels")
    except FactoryError as e:
        add("labels", False, str(e))
    return {"ok": all(c["ok"] for c in checks), "warnings": [c["check"] for c in checks if "warning" in c], "checks": checks}


# ---------------------------------------------------------------- main

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor")
    sub.add_parser("labels")
    sub.add_parser("ready")
    for name in ("ticket", "state", "claim", "worktree-remove", "promote"):
        sub.add_parser(name).add_argument("ticket")
    command = sub.add_parser("release")
    command.add_argument("ticket")
    command.add_argument("--to", required=True, choices=sorted(STOP_LABELS))
    command.add_argument("--body-file")
    command.add_argument("--repo", help="the repo whose PR stopped (default: the one the ticket's state names)")
    command = sub.add_parser("worktree")
    command.add_argument("ticket")
    command.add_argument("--slug")
    command.add_argument("--internal", action="append", default=[])
    command = sub.add_parser("base-check")
    command.add_argument("ticket")
    command.add_argument("--repo", default=CORE)
    command = sub.add_parser("checks")
    command.add_argument("ticket")
    command.add_argument("--repo", required=True)
    command = sub.add_parser("push")
    command.add_argument("ticket")
    command.add_argument("--repo", default=CORE)
    for name in ("pr-create", "pr-body"):
        command = sub.add_parser(name)
        command.add_argument("ticket")
        command.add_argument("--repo", default=CORE)
        command.add_argument("--body-file", required=True)
    sub.choices["pr-create"].add_argument("--title", required=True)
    command = sub.add_parser("pr-labels")
    command.add_argument("ticket")
    command.add_argument("--repo", default=CORE)
    command.add_argument("--add", action="append", default=[])
    command.add_argument("--remove", action="append", default=[])
    command = sub.add_parser("comment")
    command.add_argument("ticket")
    command.add_argument("--kind", required=True, choices=[k for k in KINDS if k != "review"])
    where = command.add_mutually_exclusive_group(required=True)
    where.add_argument("--repo")
    where.add_argument("--on-ticket", action="store_true")
    command.add_argument("--body-file", required=True)
    command = sub.add_parser("post-review")
    command.add_argument("ticket")
    command.add_argument("--repo", default=CORE)
    command.add_argument("--bundle", required=True)
    for name in ("backlog", "file-backlog"):
        command = sub.add_parser(name)
        command.add_argument("ticket")
        command.add_argument("--repo", default=CORE)
        command.add_argument("--bundle", required=True)
    command = sub.add_parser("comments")
    command.add_argument("ticket")
    command.add_argument("--repo", default=CORE)
    sub.add_parser("handoff").add_argument("file")
    command = sub.add_parser("issue-create")
    command.add_argument("--title", required=True)
    command.add_argument("--body-file", required=True)
    command.add_argument("--label", action="append", default=[])
    command = sub.add_parser("retro-data")
    command.add_argument("--since", help="ISO date; default: where the last retro --mark stopped")
    command.add_argument("--mark", action="store_true", help="record the newest PR seen, so the next retro starts after it")
    args = parser.parse_args()

    try:
        ctx = Context()
        if args.command == "doctor":
            result = doctor(ctx)
        elif args.command == "labels":
            result = ensure_labels(ctx)
        elif args.command == "ready":
            result = ready(ctx)
        elif args.command == "ticket":
            result = ctx.read(args.ticket)
        elif args.command == "state":
            result = ctx.state(args.ticket)
        elif args.command == "claim":
            result = claim(ctx, args.ticket)
        elif args.command == "release":
            result = release(ctx, args.ticket, args.to, read_body(args.body_file) if args.body_file else None, args.repo)
        elif args.command == "worktree":
            result = create_worktree(ctx, args.ticket, args.slug, args.internal)
        elif args.command == "worktree-remove":
            result = remove_worktree(ctx, args.ticket)
        elif args.command == "base-check":
            result = ticket_base_check(ctx, args.ticket, args.repo)
        elif args.command == "checks":
            result = run_checks(ctx, args.ticket, args.repo)
        elif args.command == "push":
            result = push(ctx, args.ticket, args.repo)
        elif args.command == "pr-create":
            result = pr_create(ctx, args.ticket, args.repo, args.title, read_body(args.body_file))
        elif args.command == "pr-body":
            result = pr_body(ctx, args.ticket, args.repo, read_body(args.body_file))
        elif args.command == "comment":
            result = post_comment(ctx, args.ticket, args.kind, read_body(args.body_file), None if args.on_ticket else args.repo)
        elif args.command == "pr-labels":
            result = pr_labels(ctx, args.ticket, args.repo, args.add, args.remove)
        elif args.command == "backlog":
            result = backlog(ctx, args.ticket, args.repo, args.bundle)
        elif args.command == "file-backlog":
            result = file_backlog(ctx, args.ticket, args.repo, args.bundle)
        elif args.command == "post-review":
            result = post_review(ctx, args.ticket, args.repo, args.bundle)
        elif args.command == "comments":
            result = {"human_comments": find_pr(ctx, args.ticket, args.repo)["progress"]["human_comments"]}
        elif args.command == "promote":
            result = promote(ctx, args.ticket)
        elif args.command == "issue-create":
            result = issue_create(ctx, args.title, read_body(args.body_file), args.label)
        elif args.command == "retro-data":
            result = retro_data(ctx, args.since, args.mark)
        else:
            result = check_handoff(ctx, args.file)
    except (FactoryError, public_text.CheckError) as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok", True) and result.get("valid", True) else 1


if __name__ == "__main__":
    sys.exit(main())
