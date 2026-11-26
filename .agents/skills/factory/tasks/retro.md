# Retro

Turn what humans had to do on merged factory PRs into proposed changes to the factory's instructions. The proposals go to a human as a draft PR; nothing here changes how the factory runs until a human merges it.

## 1. Gather

`python3 $F retro-data` lists the ace3 factory PRs merged since the last retro. For each, it gives:
- the review rounds, with their verdicts and open findings;
- the stops;
- every maintainer comment;
- `changed_after_ship`, a diffstat of what changed between the factory's last ship verdict and what merged. That diff is the work a human did that the factory didn't.

Internal repos' PRs aren't in it yet; read them on Azure DevOps when the tickets had them.

Read each PR's comments and the post-ship diff in full (`git diff <ship head> <merged head>`). With no PRs since the last retro, say so and stop.

## 2. Find the lessons

Look for what recurs, or what cost a human the most:
- a finding class that keeps coming back;
- a review round spent on something the implementer's definition of done should have caught;
- a maintainer comment that restates a rule;
- a stop that better instructions would have avoided;
- a human edit after ship that the review should have flagged.

For each lesson, name the PRs it comes from and the highest place a fix would hold, highest first:
1. a test or a check in `factory.py`, `public_text.py` or `prepare.py --check`;
2. the `ace-review` rubric or a dimension file;
3. a task brief in `tasks/`;
4. the Engineering values in AGENTS.md;
5. `bug-fix` or `tdd`.

An edit to the Engineering values is proposed, never assumed: `/ace-review` judges a branch by the base's copy, so the maintainer has to accept it.

## 3. Propose

1. Write the proposals into an issue body with the `issue-authoring` skill: one section per lesson, with its evidence (PR links, comment links), the change, where it goes, and the risks of making it. `python3 $F issue-create --title "Factory retro: <date>" --body-file <file> --label factory:ready`.
2. Make the edits on that issue's branch, as the implement task does from its step 3 (`$F claim`, `$F worktree`, commit, `$F push`, the `pr-description` skill, `$F pr-create`). Retro doesn't run review or promote. A human reads the draft PR, and may run `/factory <issue>` on it to have it reviewed.
3. `python3 $F retro-data --mark`, so the next retro starts after the newest PR this one read.

Reply with the issue and PR links and one line per lesson.
