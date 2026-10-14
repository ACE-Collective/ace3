# SVS test runs

SVS runs Atomic Red Team tests: an outside launcher registers a **run** with ACE, the test fires on a
test host, and the alerts it causes are attributed to the run instead of being triaged as real
incidents. Reviewing a run teaches SVS which signatures detect which techniques (`docs/SVS.md`,
Part 3).

This document covers how runs work in ACE and how to operate them. It grows with phase 4. Today it
covers the test hosts, the Atomic Red Team catalog, what happens to a test run's alerts once SVS
closes them, and how search treats them. The design and its reasoning are in `docs/SVS.md`; the
API's data dictionary is `docs/SVS_API.md`.

## Permissions

| Permission | Grants |
|---|---|
| `svs:run_register` | The launcher's run lifecycle calls |
| `svs:run_read` | The Runs and Tests screens, run pages, the catalog, the test hosts, coverage, and their read APIs |
| `svs:run_manage` | Ownership, cancel, close, review, candidates, ignores, manual association |
| `svs:admin` | Adding, changing and removing test hosts (and, for YARA, retiring and deleting samples) |

## Test hosts

A run can target only a **test host**: a host listed in `svs_test_hosts`. A registration against
any other host, or as a user the host doesn't list, is refused. They are a table rather than config
so a site that builds test VMs on demand adds one without restarting anything. An `svs:admin`
manages them through `/api/v2/svs/test-hosts` (and, later in phase 4, the SVS area's *Test hosts*
tab).

| Field | Meaning |
|---|---|
| `hostname` | The short name. One test host per short name. A fully qualified hostname also sets `fqdn`. |
| `fqdn` | The fully qualified name. Set it: a target named by a fully qualified name then matches only this one, so a production host that shares the short name in another domain never does. Without it, a target in any domain matches. |
| `usernames` | The users runs may use on the host. Empty means any user. |
| `ips` | The host's addresses. |
| `platform` | `windows`, `linux` or `macos` when known. A test whose `supported_platforms` doesn't include it can't target the host. |

Matching ignores case, takes a target's hostname as either the short or the fully qualified name,
and treats `CORP\alice`, `alice@corp.example` and `alice` as the same user
(`saq/svs/hosts.py::match_target`). Every change is an AUDIT line in ACE's log with the host's
fields (and, for a change, what they were before).

```bash
curl -X POST https://ace.example/api/v2/svs/test-hosts/ -H "x-ace-auth: $KEY" -H 'Content-Type: application/json' \
     -d '{"hostname": "win10-art-01.lab.example", "usernames": ["LAB\\svc_art"], "platform": "windows"}'
```

## The Atomic Red Team catalog

ACE never runs a test. It holds Atomic Red Team repositories only as a catalog: to check the test a
run is registered for, to show its name, description and commands, to check its supported platforms
and to know its ATT&CK technique.

- **Each repository is an ordinary `git_repo_<name>` section**, which `service_git` keeps checked out
  at its `local_path`, listed in `svs.catalog.repositories`. Custom repositories follow the ART
  layout and schema.
- **`service_svs` reads `atomics/T*/T*.yaml`** from the checkout whenever its commit changes,
  looking every `svs.catalog.refresh_interval_seconds`, on the primary node. If the commit moves
  while it reads (`service_git` pulled), nothing is stored and the next look reads the new commit.
- **A test is its `auto_generated_guid`.** A test without one is skipped with a WARNING, and a GUID
  already taken by another test, in that repository or another, is skipped too: the first one read
  keeps it.
- **A test that disappears keeps its row**, with `removed_at` set, so its runs keep their test. If it
  comes back, `removed_at` is cleared.
- **A test's `commit` is the commit its current version was first read from**, and its
  `content_hash` changes exactly when the test does; a new commit that doesn't touch a test leaves
  it alone.
- **A repository that can't be read** (no `git_repo_` section, no checkout yet, a broken file system)
  keeps its tests; the error is logged at ERROR, kept on the repository's row and shown by
  `ace svs catalog status`. The next successful read clears it.

```yaml
git_repo_atomic_red_team:
  name: atomic_red_team
  description: Atomic Red Team
  local_path: data/git/atomic-red-team
  git_url: https://github.com/redcanaryco/atomic-red-team.git
  branch: master
  update_frequency: 3600

svs:
  catalog:
    repositories: [atomic_red_team]
    refresh_interval_seconds: 300
```

```bash
ace svs catalog status                 # each repository's commit, test count and last error
ace svs catalog refresh [--force]      # read now; --force reads an unchanged commit again
```

The catalog is read through `/api/v2/svs/tests` (`svs:run_read`): filter by technique (`T1059` also
finds its sub-techniques), name, platform, executor, repository or `removed`.

## Test alerts and `SIMULATED`

When a run is reviewed or closed, SVS gives every alert fully attributed to it the disposition
**`SIMULATED`**. Nothing sets it yet: the run review that sets it arrives later in phase 4.

| Setting | Value | Meaning |
|---|---|---|
| class | tp | the detections did detect the (simulated) activity, so reviewed runs grade their YARA hits as TP samples (`docs/SVS_SAMPLES.md`) |
| `analyst_selectable` | false | only ACE sets it; the disposition modals don't offer it and the server rejects it |
| rank | 55 | below `GRAYWARE`: an event holding a test alert and a real one rolls up to the real one |
| `stop_analysis_on_dispositions` | listed | the engine stops correlation analysis on it |

SVS sets it through the same disposition writer analysts use (`set_dispositions(..., system=True)`
in `saq/database/util/alert.py`). That writer requeues the alert into the `dispositioned` mode, so
capture runs on a reviewed run's alerts as it does on any graded alert.

### A `SIMULATED` alert is frozen

Its detections, and so their verdicts and the sample labels derived from them, are fixed when its
run is reviewed, so a report about the run stays reproducible. ACE therefore refuses everything that
would change them. The general rule is the `analyst_selectable: false` flag, not the name: an alert
whose current disposition is configured that way is *frozen* (`is_frozen_disposition()` in
`saq/disposition.py`).

- **Its disposition can't be changed by hand.** The alert page's and manage page's disposition, the
  event page's bulk disposition and a review that corrects the disposition all leave a frozen alert
  alone and say so: *"left 1 SIMULATED alert alone (only ACE sets that disposition)"*. A review that
  finds the disposition correct is still recorded. To treat a test alert as a real one, it is
  disassociated from its run (a later phase-4 change), which gives it back to analysts.
- **It is never reset or re-analyzed, and gets no new observables.** Each of these refuses a
  frozen alert with *"alert … is SIMULATED, a disposition only ACE sets: it can't be reset,
  re-analyzed or given new observables"*:
  - `ace alert reset` and `ace alert analyze` / `reload` (the alert is skipped and the error logged);
  - the GUI's *Analyze*, uploading a file to the alert, *Add observable*, and the observable actions
    (collect file, crawl/render, check for clickers);
  - `GET /api/analysis/resubmit/<uuid>` (v1) and `POST /api/v2/alerts/bulk-add-observable` (a per-alert
    failure).
- **Its verdict chips are read-only.** The run review owns those verdicts (`docs/SVS.md`, Part 1).

Tags, comments and ownership changes still work on a frozen alert.

### Test alerts in search

Test-run alerts are routed to their own queue, `svs.queue` (default `svs`; the routing arrives
later in phase 4). Alert search and *similar alerts* leave that queue out whenever a request says
nothing about queues, so "have we seen this before?" is answered from real alerts, and they say
how many test alerts they left out (`docs/SEARCH.md`, *Read path*):

- **The manage page's search box** shows *"3 test-run alerts left out. Include them"* under the
  result count; *Include them* re-runs the search with them, and *Leave them out* undoes it.
- **`POST /api/v2/search/alerts` and `/similar`**, and the AI API's `/ai/v1/search/*`, take
  `include_test_alerts` and answer `excluded_test_alerts`.
- **`ace search query` and `ace search similar`** take `--include-tests`.
- **Naming a queue** (`queue:svs`, a Queue filter, the `queues` field) always gets exactly that
  queue, test queue included.

`GET /api/v2/alerts`, the export listing, returns test alerts like any other; leaving them out is
the caller's choice. Prevalence and disposition history count only the `default` queue, so test
alerts were never in those.

```yaml
svs:
  queue: svs
```

### Retention

`SIMULATED` alerts are **archived** after `svs.simulated_days` (default 30), the way
`FALSE_POSITIVE` alerts are archived after `global.fp_days`, and they are **never deleted**.
`archive()` frees the analysis details and the derived files, and keeps the alert row, its
disposition and its detection points. Those are what the verdicts, the sample labels and the run
attributions derive from: deleting the alert would orphan all three.

The daily `ace alert cleanup` does it (`etc/cron/daily/alert-cleanup`). To archive with another
age, or to count what would be archived:

```bash
ace alert cleanup --simulated-days-old 7
ace alert cleanup --dry-run --simulated-days-old 0
```

```yaml
svs:
  simulated_days: 30   # at least 1
```
