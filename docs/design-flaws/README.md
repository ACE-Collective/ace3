# Design flaws

Each `<id>.yaml` here is a flaw in ACE's design that a change had to work around. The flaw was too much work to fix inside that change, so it was kept here to fix later. `/ace-review` writes these files (`.claude/skills/ace-review/rubric.md`, "Design flaws worked around"), and every review reads them, so a flaw found once is recognized again in the next change that works around it.

A file records:
- the flaw, and a sketch of the real fix with its size;
- its `status`: `undecided`, `deferred` (keep going, fix it later), `addressing` (being fixed first) or `wrong` (not a flaw; reviews skip it);
- every branch that works around it, and where.

The number of workarounds is the cost of leaving the flaw unfixed, so the flaws with the most workarounds are the first to fix. List them with:

```bash
/venv/bin/python .claude/skills/ace-review/scripts/findings.py flaws
```

`findings.py flaw <id> defer|address|wrong` records a decision. The PR that fixes a flaw removes its file (`findings.py flaw <id> fixed`) and the workarounds it lists.

A new flaw file is committed with the branch whose review found it, so it reaches `main` with the change that works around it.
