---
name: pr-description
description: Write the PR description for a finished ACE bug fix or feature and put it on the PR, through factory.py in a /factory run. Covers what to include (including the Testing section and the Site operators section that calls out what a site must change on upgrade: compose overlay, configuration, integration code, manual steps), the repo-scoping rules that decide how many descriptions to write (a working tree spans the public ace3 core plus the separately versioned integrations/ and signatures/ repos), what detail each repo may carry, and the length limit on internal-repo PRs.
---

# PR descriptions

A finished bug fix or feature gets a Markdown description of the change, one per repo that has a PR.

## Where it goes

Write it to a scratch file and hand it to whatever opens the PR. Don't keep a copy in `local/`: the PR is where the description lives.

- **A `/factory` run:** `factory.py pr-create` or `factory.py pr-body`, which check it for internal detail and put it on the PR.
- **Outside the factory:** `gh pr create --body-file <file>` for ace3, after `python3 .agents/skills/factory/scripts/public_text.py --file <file>` finds no internal term in it; `az repos pr create --description` for an internal repo.

## Content

Summarize the problem, the fix, and how it was verified. Match the length to what the change needs: cover the substance without filler sections or redundant summaries. Apply the `unslop` skill.

Every description has a **Testing** section (AGENTS.md, *Tests*): the commands run, their pass/fail counts, the run that failed before the fix and passed after it for each behavior, the changed-line coverage, and any manual or live checks (`verify-ace-engine`, `verify-ace-gui`). Say plainly what was not run.

## Site operators

Each site runs ACE from its own production compose overlay, its own configuration and its own integrations, none of which a merge updates. An operator learns what an upgrade needs from them by reading the PR. So when a change needs an operator to act, or changes what their site does on upgrade, the description has a **Site operators** section right after the opening line (`Fixes #N`) and before everything else. Never leave it as a follow-up or a footnote at the end, where it gets missed.

It is needed when the change does any of these:

- Adds, removes or renames a compose service, or changes one's command, volumes, ports, environment or profile. The root `docker-compose.yml` is the dev stack, so production gets none of it until the overlay is changed to match.
- Adds a config key a site must set, renames or removes a key, changes a default, or makes a config that used to load fail validation (an unknown key now rejected, a value no longer accepted).
- Needs a new environment variable, secret, password file, volume, port or external service.
- Changes what integration code depends on: a base class, a hook or registration point, a function signature, an import path, a config hook (`docs/INTEGRATIONS.md`). Say what an integration has to change, with the old and new form.
- Has a migration that takes long or locks a large table, or needs a manual step: a backfill, a one-off command (`ace ... migrate`), a cron entry, a logrotate line.
- Changes behavior on upgrade with nothing else done: something new that runs, alerts, deletes, remediates or changes what analysts see.
- Ships a feature that is off by default. Say how to turn it on, and how to try it safely first (a dry run, one node) if there is a way.

To find them, read the diff of `docker-compose.yml`, `etc/saq.default.yaml`, `saq/configuration/schema.py`, the `alembic/*/versions/` directories, `etc/cron/`, `etc/logrotate.conf` and anything `docs/INTEGRATIONS.md` documents, and ask what a site that changes nothing gets on upgrade.

Write it as numbered steps, in the order an operator does them. For each step, give what to do, where (the file, key or command), and what happens if it is skipped. Mark the steps that happen by themselves (a migration `ace-setup` applies) as automatic. Give config as a block that can be copied. When the change needs nothing from an operator, leave the section out rather than writing "none". In ace3 the section stays generic like the rest of the description: "your production compose overlay", "your probe's name", never a site's own names.

## Repo scoping

A working tree spans more than one upstream repo, and PR descriptions are per repo:

- **Write one only for a repo with committable changes.** Check each repo's own status (`git status` for the core, `git -C integrations/<name> status`, `git -C signatures status`). A repo whose only changes are gitignored, untracked or dev-only (notably `etc/saq.yaml`, or an untracked `CLAUDE.md`) has no PR and gets no description.
- **A change confined to one repo** gets one description. **A change that spans several** gets one per repo, each covering only that repo's files.

## Detail sensitivity

It follows the repo:

- **ace3 is public.** Never put internal or customer detail in it: company or integration names, internal hostnames, mailbox addresses, alert UUIDs, log index names. Make the useful content generic. A description of an ace3 PR never names or links the internal repo's PR. A `/factory` run enforces this with each internal repo's `.factory/public-denylist.toml`, but a denylist catches names, not descriptions, so the rule still applies to what you write.
- **The integration and signatures repos are internal.** Internal company and integration detail is fine there, but no live customer specifics (real mailbox addresses, alert UUIDs). Their PR may link to the matching ace3 PR.

## Length limit for internal repos

The internal repos are hosted on Azure DevOps, which caps a PR description at 4000 characters. Keep each internal description under that: tighten the prose and trim detail rather than split it. The ace3 description has no cap, but shouldn't ramble.
