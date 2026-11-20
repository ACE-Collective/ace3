---
name: pr-description
description: Write the PR description for a finished ACE bug fix or feature and put it on the PR, through factory.py in a /factory run. Covers what to include (including the Testing section), the repo-scoping rules that decide how many descriptions to write (a working tree spans the public ace3 core plus the separately versioned integrations/ and signatures/ repos), what detail each repo may carry, and the length limit on internal-repo PRs.
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
