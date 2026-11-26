---
name: issue-authoring
description: Write and file an ACE issue, either an ace3 GitHub issue or an Azure DevOps work item for an integration or signatures, for a bug, a feature, a design flaw or a pre-existing finding. Covers searching for an existing one, which tracker it goes in, what the body carries (the problem and its evidence, the proposed change, its tests, and a Risks section naming what could break in making the change), the detail a public issue may carry, the title and the labels. Use when asked to file, open, write or draft an issue, ticket or work item in this project, or to write one that /factory can build from.
---

# Issues

An issue says what is wrong or missing, what it costs, what to change, and what could break in changing it. A maintainer reads it to decide whether the work is worth doing. Once a maintainer labels it `factory:ready`, `/factory` builds from it with no one to ask, and sends it back as `factory:needs-info` when it leaves a decision open (`factory/tasks/implement.md`, step 2). Write it so it can be built from the text alone.

## Before writing

- **Search for an existing one**, open and closed: `gh issue list --state all --search "<terms>"`, and `gh issue list --label "design flaw" --state all` for a flaw. A closed issue was either fixed or decided against, and filing it again reopens that decision. When one exists, tell the user and offer a comment on it instead.
- **Read the code it is about.** Cite `file:line`, the function, the text of the log record. When running something would settle a claim (a repro, a query, a log search), run it. An issue built on guesses gets sent back for more information, or gets the wrong thing built.
- **Read the subsystem's section of `docs/DESIGN_INVARIANTS.md`** and its design doc in `docs/`. Most of the risks come from there.

## Where it goes

The tracker follows the code:

- A change to core is an ace3 issue.
- A change to an integration's or `signatures`' own code is a work item in that repo's Azure DevOps project, named under `azure_devops` in its `.factory/config.toml`.
- A flaw in core found through an internal repo is an ace3 issue, written in core's terms.
- A change that needs both is an ace3 issue for the core part, written generically (a hook, a config key), plus a work item for the internal part that links to it. The ace3 issue never names or links the work item.

Show the user the title, labels and body, and file once they approve, unless they told you to file it directly. To file:

- **ace3:** write the body to a scratch file, then `python3 .agents/skills/factory/scripts/factory.py issue-create --title <title> --body-file <file> --label <label> ...`. It checks the title and body against every internal repo's denylist, refuses when one is missing, and files the issue only when nothing matched. Never file with `gh issue create` directly, which skips the check. On a refusal, reword the text generically, never the denylist.
- **Azure DevOps:** `az boards work-item create --project <project> --type <type> --title <title> --description <html>`. The description field is HTML, so convert the Markdown first; `/factory` files defects as `Bug`.
- **In a `/factory` run:** `file-backlog` builds each body from the review's finding or flaw, with the reviewer's `risks` as its Risks (`ace-review/rubric.md`). An entry in `$B/backlog.json` may carry `title` and `body` to replace them (`factory/tasks/review.md`, *File the backlog*). Write those with this skill, Risks included.

## The body

In this order. Give each part a heading once the issue runs past a few paragraphs.

1. **The problem**, as the opening paragraph with no heading. Say what happens, where, and what it costs in the terms of AGENTS.md's *Engineering values*: downtime, an alert that never fires, a failure nobody hears about, a production failure the logs can't explain, untested code, an analyst waiting. Give numbers where you have them.
2. **Evidence.** The `file:line` references and log records. For a bug, give the repro: the command or input, what happened, what should have happened, and the commit or release it was seen on. For a regression, give the release it started in when you know it.
3. **Proposed change.** Make it specific enough to build: the config key with its type and default, the functions that change, the behavior in each case. Settle every decision a builder would otherwise guess at. One you can't settle goes under **Open questions**, each with its options, and then the issue isn't ready for `/factory` until a maintainer answers it. Say what must stay the same when someone could reasonably change it.
4. **Tests.** The behaviors to test, failure paths included. For a bug, name the test that fails before the fix.
5. **Risks.** See below.
6. **Out of scope**, when there is any: what you noticed that belongs in another issue.

A small issue, such as a missing traceback, takes a few lines: the problem, where it is, the fix, the risks. Leave out sections that would be empty, except Risks, which every issue has.

## Risks

The Risks section names what could break, or get worse, because of the proposed change. The cost of leaving the problem alone goes in the problem statement, not here.

Each risk opens with its level and whether anything guards it, then says:

- what breaks and for whom (which processes, nodes, alerts or analysts);
- what triggers it and how often that happens, in words;
- how anyone would find out, or that nobody would;
- what guards against it: a test, a default that keeps today's behavior, a check to run before merging. When nothing does, the risk is **unguarded**: say so in its opening and why that is acceptable.

The level rates the harm if it happens, not how likely it is. Likelihood goes in the text, where a reader can check it.

- **High:** blocker-class harm by `ace-review/rubric.md`'s *Severity*. A service goes down, hangs or can't restart; data is lost or corrupted; a live table locks; an event that should alert is dropped; a failure is hidden from operators; a security hole opens.
- **Medium:** a wrong result, a broken failure path or a performance regression, with limited blast radius, that a test, a log record or a monitor would show.
- **Low:** extra work, noise or inconvenience, and no wrong result.

List them high first. A high risk that is unguarded is the one a maintainer has to see, so never soften its level because it seems unlikely. Check the change against each of these, and write up only what applies:

- **Running nodes.** A service's start, run or stop path, a lock, a wait, a worker's lifetime. During a deploy a cluster runs two versions at once, so an old node reads what a new node wrote: `data.json`, rows, CAS objects, encrypted files, node-to-node API calls.
- **Stored data.** Saved alerts load through the new code, so a new `data.json` key is optional on read. A persisted name (an Analysis class's `MODULE_PATH`, an observable type, directive, disposition or analysis mode) is never renamed (`docs/ENGINE.md` §15).
- **Database.** A migration's lock or full-table copy on a large live table, the partition rules (`docs/DATABASE_PARTITIONS.md`), an unbatched update or delete, a lock order that deadlocks against an existing transaction.
- **Detection.** Whether the change can drop an event that should alert: a filter, exclusion or suppression, a cached answer read after the data behind it changed, a module no longer run in some analysis mode, a change to the observable type hierarchy.
- **Configuration.** A changed default changes behavior at every site on its next deploy. A removed or renamed key is silently ignored in most sections (#1247), so the configs that still set it stop working without an error.
- **Performance and memory.** New work per page render, per request or per observable. A query per row. An import added to a module every process loads (`docs/IMPORTS.md`).
- **Security.** Permission checks, the sandbox allowlists (never widened), output escaping, secrets reaching a log, file paths taken from analyzed content.
- **Callers.** Integrations that call or subclass what changes (search `integrations/` explicitly, since `rg` skips it), API v2 clients, scripts that pass a CLI option.
- **Rollback.** Whether reverting the PR undoes the change: a migration that can't be downgraded, or data written in a format the old code can't read.

When nothing applies, say in one sentence why the change can't break anything, with the level **None** ("**None.** Changes one log call's level and arguments; no behavior changes."), not a bare "None".

```markdown
## Risks

- **High, unguarded.** A site that sets the limit below its real start time keeps its engine from ever starting. It takes an operator lowering the limit below the default, and nothing checks the value against a measured start time. That is acceptable because the failure is loud: the engine exits at start, and its ERROR record names the worker and the limit.
- **Medium.** An engine that can't start takes longer to fail. A site that raises the limit to 300 s waits five minutes before a stuck worker fails the engine's start (the behavior #978 added). It happens only at a site that raises the limit. *Guard:* the default stays 30 s, so nothing changes until a site sets it, and the setting's description says what a larger value costs.
```

## Detail

The rules are the `pr-description` skill's *Detail sensitivity*. ace3 is public: no company or integration names, internal hostnames, mailbox addresses, alert UUIDs, Message-IDs or log index names. Describe production evidence generically ("one node of a development instance") and keep the numbers. `public_text.py` catches names on the denylist, not descriptions, so the rule also binds what you write. A work item may carry internal detail but no live customer specifics.

## Title and labels

The title names the defect or the behavior wanted, in sentence case with no prefix: "continue_analysis logs a failed execute_query without its traceback", "Make the engine's worker start timeout configurable".

Labels are only those the repo has (`gh label list`): the kind (`bug`, `enhancement`, `refactoring`, `documentation`), each area it touches (`logging`, `performance`, `tests`, `GUI`, `security`, `DevEx`), `design flaw` for an issue that describes one, and `breaking change` when the proposed change removes or renames a config key, an API field or a CLI option. Never add a `factory:*` label. Those labels hold the ticket's state, and only a maintainer adds `factory:ready`. The one exception is the `factory:ready` that `/factory retro` puts on its own issue (`factory/tasks/retro.md`, *Propose*), which its next step claims.

Apply the `unslop` skill to the title and body.
