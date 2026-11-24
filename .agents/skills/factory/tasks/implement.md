# Implement

Take one ticket from `factory:ready` to a draft PR, or to a clear stop. Run every `$F` command on the host. Run tests and `ace` commands from the worktree's root through `bin/exec-in-container.sh` (AGENTS.md, *Where a command runs*).

Run every pytest command in the background (Claude Code's `run_in_background`), with its output redirected to a file outside the worktree, and read that file when the run exits. A run waits while any other run of the suite holds the dev container, maybe another ticket's, and a foreground command that times out while it waits kills only the `docker exec` client: the run goes on in the container and runs the tests later, for nobody. While a run you started is still going, don't start another or remove the worktree.

Wait for a background command by its exit notification, never with a polling loop. A loop whose condition never comes true outlives the task: it keeps the subagent open after its handoff and polls until someone kills it. If a command must wait on another inside one shell, wait for a line the command writes itself when it ends (`...; echo "exit=$?" >> <file>`, then `grep -q '^exit=' <file>`), give the loop a limit (`for i in $(seq 200); do ...; sleep 3; done`), and don't parse another tool's output or use `pgrep -f`: its pattern is in the loop's own command line, so it always finds the loop. Before you write the handoff, stop every background command you started that is still running.

## 1. Claim

`$F claim TICKET`. It refuses a ticket someone else holds; stop there and report it. Claiming comes before any other work, so two runs never build the same ticket.

## 2. Read the ticket against the code

Read the ticket and its comments with `$F ticket TICKET` (it shows only maintainers' comments, and all of a work item's, which `az boards work-item show` doesn't). Then do a bounded read of the code it names: enough to say what changes and where, not the whole fix. Decide one of:

- **Clear enough to build.** Go on.
- **Vague, or the fix needs a design decision** (more than one reasonable behavior, a change to a public interface or config the ticket doesn't settle, a design flaw the ticket doesn't decide). Write the specific questions, each with the options you see, into a file, then `$F release TICKET --to needs-info --body-file <file>`. Write the handoff with `next_state: needs-info` and stop. Don't guess.
- **The change belongs in an internal repo** (an integration or `signatures`) as well as, or instead of, ace3. That is fine; note which repos for step 3.

## 3. Worktree

`$F worktree TICKET --slug <3-5 words> [--internal <name> ...]`, one `--internal` per internal repo the change touches. It prints the worktree's path, which you work in from now on, and the branch, the same name in every repo. Never edit the main checkout. A resumed ticket (its branch already pushed) starts from the pushed branch: read what is there before adding to it.

## 4. Build

- A `bug` ticket: follow the `bug-fix` skill. **No confirmed repro means no fix**: if you can't make it fail on demand, comment what you tried and found (`$F comment TICKET --kind note --on-ticket --body-file <file>`), `$F release TICKET --to needs-human --body-file <file>` with the one-line reason, and stop.
- Every change: follow the `tdd` skill. Each behavior gets a test seen to fail before the code and pass after. Keep both runs' output for the PR.
- Follow AGENTS.md as written, especially *Engineering values* and *Conventions*. One concern: anything else you notice goes in the PR body under *Follow-ups*, not in the change.
- Internal repo detail stays in the internal repo. An ace3 change that an integration needs is written generically (a hook, a config key), never naming the integration.

## 5. Definition of done

All of these, before the PR opens:

- `bin/exec-in-container.sh /venv/bin/python .agents/skills/ace-review/scripts/prepare.py --check` prints nothing (and `--repo integrations/<name>` or `--repo signatures` for each internal repo touched).
- The tests of the touched paths pass: `bin/exec-in-container.sh pytest <paths> -n auto`. An integration's tests run by their own path, `integrations/<name>/tests`.
- Changed-line coverage: `pytest --cov --cov-report=xml` on those tests, then `diff-cover coverage.xml --compare-branch=origin/main` (AGENTS.md, *Tests*).
- An analysis module, engine or YARA change: the `verify-ace-engine` skill. A GUI change: the `verify-ace-gui` skill. When the skill isn't available in this checkout, say so in the PR body's Testing section instead.
- Each internal repo touched: `$F checks TICKET --repo <name>`, which runs every `[[check]]` in its `.factory/config.toml` on what the branch changes, and must report `ok`.
- A model change: the matching `make *-db-check`.

If a check can't pass and you can't see why after two attempts on the same idea, stop with `needs-human` and say what you tried.

## 6. Commit, push, open the PR

1. Commit in each repo touched, in small commits whose messages say why. End each message with the attribution line your instructions give. No internal detail in an ace3 commit.
2. `$F push TICKET --repo <name>` for each repo. For ace3 it checks the commits, their messages, the added lines and the branch name against the denylists first, and refuses on a match: fix the commit (amend or rewrite your own unpushed commits), don't work around the check.
3. Write the PR body with the `pr-description` skill, *A `/factory` run*: what the ticket asked, the fix, the Testing section with the red and green runs, coverage and live checks, and *Follow-ups*. One body per repo. An internal repo's body may link the ace3 PR; the ace3 body never names the internal one.
4. `$F pr-create TICKET --repo <name> --title <title> --body-file <file>` for each repo. ace3 first, so the internal PR can link it. The ace3 PR gets `Fixes #N` for a GitHub ticket.
5. Label each PR: `$F pr-labels TICKET --repo <name>` prints the repo's labels, then `--add <label>` once per label. Give it the kind of change (`bug` for a fix, `enhancement` for a new feature, `refactoring`, `documentation`) and each area it is about (`logging`, `performance`, `tests`, `GUI`, `security`), and `breaking change` when it removes or renames a config key, an API field or a CLI option. Only labels the repo has. `design flaw` labels the issue that describes a flaw, not the PR that fixes one, and the `factory:*` labels are the ticket's state, which `pr-labels` refuses.

## 7. Clean up and hand off

`$F worktree-remove TICKET`. It refuses while anything is uncommitted or unpushed; that is a bug in this run, so fix it rather than force it. Then write the handoff:

```json
{"task": "implement", "repo": "ace3", "ticket": "<TICKET>", "pr_url": "<ace3 PR, or the internal one if there is no ace3 PR>",
 "branch": "<branch>", "head_sha": "<that PR's head>", "verdict": null, "findings_open": [], "next_state": "review", "stop_reason": null}
```

A run that made no commits never hands off to review: it stops with `needs-human` and says why.
