# SVS test runs

SVS runs Atomic Red Team tests: an outside launcher registers a **run** with ACE, the test fires on a
test host, and the alerts it causes are attributed to the run instead of being triaged as real
incidents. Reviewing a run teaches SVS which signatures detect which techniques (`docs/SVS.md`,
Part 3).

This document covers how runs work in ACE and how to operate them. It grows with phase 4. Today it
covers the test hosts, the Atomic Red Team catalog, how a launcher registers and drives a run, the
run states and timers, refused registrations, how alerts are attributed to runs and routed to the
test queue, what a run found (its result) and the expectations and ignores it is judged by, what
happens to a test run's alerts once SVS closes them, how a person reviews, closes and owns a run,
and how search treats test alerts. The SVS screens arrive later in phase 4. The design and its
reasoning are in `docs/SVS.md`; the API's data dictionary is `docs/SVS_API.md`.

## Permissions

| Permission | Grants |
|---|---|
| `svs:run_register` | The launcher's run lifecycle calls |
| `svs:run_read` | The Runs and Tests screens, run pages, the catalog, the test hosts, coverage, and their read APIs |
| `svs:run_manage` | Ownership, cancel, close, review; a test's expectations, ignores and settings; manual association |
| `svs:admin` | Adding, changing and removing test hosts; global ignores (and, for YARA, retiring and deleting samples) |
| `alert:write` (existing) | From an alert's page, *Disassociate from run* and *Not a test* (*Test alerts in the alert list and on the alert page*) |

## Test hosts

A run can target only a **test host**: a host listed in `svs_test_hosts`. A registration against
any other host, or as a user the host doesn't list, is refused. They are a table rather than config
so a site that builds test VMs on demand adds one without restarting anything. An `svs:admin`
manages them on the SVS area's *Test hosts* tab, or through `/api/v2/svs/test-hosts`.

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

- **Each repository is an ordinary `git_repo_*` section**, named by its `name` field, which `service_git` keeps checked out
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
- **A repository taken out of `svs.catalog.repositories`** is no longer read, so the next refresh
  removes its tests (`removed_at` set, as for a test that disappears; their runs keep them) and logs
  a WARNING naming it and the number of tests removed. Its row keeps that as its error, so
  `ace svs catalog status` shows it and, if it is listed again, the next refresh reads it again
  whatever its commit and its tests come back. So a misspelled name retires the real repository's
  tests until the name is fixed: check for that WARNING after editing the list.

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

`GET /api/v2/svs/catalog/repositories` (`svs:run_read`) serves the same status. A launcher checks
out the `commit` it names to run each test as the catalog has it, including the `src/` files a
test's `content_hash` doesn't cover (`docs/SVS_API.md`, *Catalog repositories*).

The catalog is read through `/api/v2/svs/tests` (`svs:run_read`): filter by technique (`T1059` also
finds its sub-techniques), name, platform, executor, repository or `removed`.

### Tests and their state

`GET /api/v2/svs/tests` lists the catalog with each test's state (`docs/SVS_API.md`, *Tests*). A
test is judged on each platform on its own: by its latest reviewed run on that platform, as signed
off, against what is expected of it there (*Expectations and ignores*, below).

| State on a platform | Meaning |
|---|---|
| `awaiting_review` | no run of it there is reviewed yet, or something was expected of it there only after its latest review there |
| `no_expectations` | it has a reviewed run there, and nothing is expected of it there |
| `failing` | its latest reviewed run there missed an expected signature |
| `stale` | it would be validated, but the test or an expected signature's rule changed since that review |
| `validated` | its latest reviewed run there hit every expected signature |

The test's own state is `never_run` when no run was ever registered for it. Otherwise it is the
worst of the states of the platforms it has a run or a decision on, in this order: `failing`,
`stale`, `awaiting_review`, `validated`, `no_expectations`. So a test validated on windows and not
yet reviewed on linux is `awaiting_review`. The test's detail lists every platform's state
(`platform_states`), with `never_run` for a supported platform it has no run or decision on.

Each row also has its run count, its latest run and latest reviewed run (on any platform), how many
signatures are expected of it on any platform, and how many of its latest 5 ended or reviewed runs missed an expected signature.
Nothing suggests what to run next: that stays the team's call. The GUI's Tests tab and each test's
page show the same (*In the GUI*, below).

## Registering a run

ACE never runs a test. A **launcher** outside ACE (a script around `Invoke-AtomicTest`, a CI job, a
person with `curl`) drives each run through `/api/v2/svs/runs` with an API key holding
`svs:run_register`:

| Call | Does |
|---|---|
| `POST /api/v2/svs/runs/` | Registers a run for one catalog test against one or more test hosts. Answers 201 with `run_id` and the run's **marker**. |
| `POST /api/v2/svs/runs/{run_id}/start` | The test is about to fire: the windows start now, at the whole second (a stored time has no fraction, so the window never starts after the call). 409 when another run holds a target's host. |
| `POST /api/v2/svs/runs/{run_id}/executed` | Optional. How the test executed: a non-zero `exit_code` or an `error` moves the run to *error*. `output` is what the test printed (*The test's output*, below). |
| `POST /api/v2/svs/runs/{run_id}/cleanup` | Optional. The test's cleanup begins now (*Cleanup*, below). |
| `POST /api/v2/svs/runs/{run_id}/cancel` | Stops the run. |
| `POST /api/v2/svs/runs/validate` | Optional, a dry run. Takes the registration's body and answers what registering it would decide, without registering it (*Validating a registration*, below). |

```bash
curl -X POST https://ace.example/api/v2/svs/runs/ -H "x-ace-auth: $KEY" -H 'Content-Type: application/json' \
     -d '{"test_guid": "5c16ceb4-ba3a-43d7-b848-a13c1f216d95",
          "targets": [{"hostname": "win10-art-01", "username": "LAB\\svc_art"}],
          "launcher": "nightly-art", "batch_id": "2026-10-14", "extra": {"job": 1234}}'
# {"run_id": "…", "marker": "svs-3yq4…", "state": "created", "observation_seconds": 3600, …}
curl -X POST https://ace.example/api/v2/svs/runs/$RUN/start -H "x-ace-auth: $KEY"
```

- **`test_guid`** is a test's `auto_generated_guid` in the catalog (`/api/v2/svs/tests`). A test
  that is not there, or that was removed, is refused with 422.
- **`targets`** are test hosts, by short or fully qualified name, each with the user the test runs
  as. A target that is not a test host, or a user the host doesn't list, refuses the whole
  registration with 403 (below). A test whose `supported_platforms` doesn't include a target's
  `platform` is refused with 422. At most `svs.runs.max_targets` (16).
- **Every run is on one platform** (`platform`, in the answer and on every read), the grain coverage
  is judged on:
  - the platform of its targets' test hosts, which have to agree; a host without a `platform` is
    taken to be on the others';
  - when no target's host has one, the test's only supported platform, as ATT&CK names it
    (`iaas:aws` is `iaas`, `azure-ad` is `identity-provider`, `office-365` and
    `google-workspace` are `office-suite`).

  Hosts on different platforms, or a test that supports more than one platform with no target's
  host saying which, are refused with 422, without an alert. Set the test hosts' `platform` and a
  launcher never meets the second case.
- **`launcher`** is required (422 without it): a name for the launcher, 1 to 256 characters, kept
  with the run and in every log record of its calls. It is a label: any name is accepted, and it
  grants nothing (the API key does). **`batch_id`** (optional) is a label shared by runs registered
  together; **`extra`** (optional) is any JSON object the launcher wants kept with the run, at most
  `svs.runs.max_extra_bytes` (16 KiB) serialized. It is stored and shown on the run page.
- **One run per test host.** A target whose test host another run holds is refused with 409, naming
  that run (*One run per test host*, below). It creates no alert.
- A call that doesn't apply to the run's state (starting a run twice, `executed` before `start`)
  answers 409 with the run's current state. Each call, accepted or not, is in the run's event log
  with its payload.

### Validating a registration

`POST /api/v2/svs/runs/validate` takes the same body as `POST /api/v2/svs/runs/` and the same
permission, and answers 200 with what registering it would decide (`docs/SVS_API.md`, *Runs*):

- `decision` is `accepted`, `refused`, `invalid` or `host_busy`, and `status_code` is what
  registering would answer (201, 403, 422 or 409). An invalid registration's `message` is the 422's
  detail; each target of a busy one lists the runs holding its host (`held_by`).
- `targets` judges each target as registering would: whether it is accepted, why not, and the test
  host it names with that host's platform. It is empty when the registration is invalid before its
  targets are judged (a test not in the catalog, too many targets, `extra` too large).
- An accepted registration also has the run's `platform`, `observation_seconds` with its
  `observation_source`, `attribution_seconds` and `holds_host`.

It only reads: no run, no event, no refusal row and no alert, so a launcher can check itself
against production ACE and triage sees nothing. Each call is logged at INFO with the caller (`call`
`validate`, `outcome`, `reasons`). What it reads can change before the launcher registers (a test
host edited, an expectation decided), so registering still decides for itself.

### The test's output

`executed` takes `output`, what the executor printed (stdout and stderr), so a reviewer can see why
an expected detection is missing. It is kept with the run (`launcher_output`) and shown on the run
page, folded, under *Output*. Up to 64 KiB is kept as sent; longer output keeps its start and its
last 16 KiB, where errors usually are, around a marker saying how many bytes were left out. The
event log records the size the launcher sent and whether it was truncated, not the text.

### Cleanup

Atomic tests clean up after themselves (`cleanup_command`), inside the run's window, and what the
cleanup does can fire signatures that are not what the test is about. A launcher that calls
`POST /api/v2/svs/runs/{run_id}/cleanup` just before it runs the cleanup records when it began
(`cleanup_at`), on a `started` run, once (409 in any other state, and the second time). The call is
in the event log like the other launcher calls.

- **Which detections.** Each attribution keeps the alert's event time it was judged by
  (`event_time`); one at or after `cleanup_at` is the cleanup's (`cleanup` on the attribution and on
  the run's alert). One written before event times were kept is the test's.
- **Still the run's.** Its alerts are routed to the test queue, closed with the run and kept or
  marked not a test like any other.
- **Left out of what the run teaches.** A signature the test fired outside its cleanup is counted
  by those alerts alone. One that fired only during the cleanup is `cleanup` in the result: never a
  candidate, so a review never proposes it as an expectation. If it is expected, it is `missing`.
  An analyst can still decide it by hand on the test (*Expectations and ignores*).
- **On the run page,** the result lists what fired only during the cleanup apart, after the rest,
  and the alerts and detections say *cleanup*.

### The marker

Every run gets a **marker**: `svs-` followed by 26 base32 characters (128 random bits, lower case,
`saq/svs/markers.py`). The launcher puts it where the test's process telemetry shows it, so the
alerts the test causes can be told apart from real ones:

- as an input argument the test passes to its command (`Invoke-AtomicTest -InputArgs`), when the
  test has a free-text or output-name argument;
- or as a trailing comment on the executor's command, in a per-run copy of the test's YAML:
  `& REM svs-…` for `command_prompt`, `# svs-…` for `sh` and `bash`, `<# svs-… #>` for `powershell`.

The marker is not a secret. It counts only for its own run, on its own targets, inside its window
(`docs/SVS.md`, Part 3, *Markers*).

**Markers inside files.** A marker can also end up in a dropped script or document rather than in a
command line. ACE ships a YARA rule, `SVS_Marker` (`saq/svs/marker_rule.py`), that finds the same
markers in file contents, as ASCII or UTF-16 text:
- **Where it lives.** The `yara` service writes it to `<service_yara.signature_dir>/svs_marker/svs_marker.yar`
  when it starts, before it loads any rules, so its own namespace is loaded and watched with the
  rest. The engine's fallback scanner does the same before it loads rules.
- **When it is rewritten.** Only when ACE's copy of the rule changes (an upgrade). A rewrite with
  the same bytes would recompile every rule, so an unchanged file is left alone.
- **It never alerts** (`modifiers = "no_alert"`). A match is kept in the file's *Yara Scan Results*,
  with the matched marker, and that is what attribution reads.
- **It is not a signature.** Like `observable_export/`, the directory is left out of the Signatures
  inventory and has no uuid.
- **Don't edit it, and don't commit it.** An edit is overwritten at the next start. When
  `signature_dir` is inside a rules repository's checkout, `svs_marker/` shows up there as
  untracked: don't commit a directory of that name to the repository.

## One run per test host

Context attribution needs exactly one run that could have caused an alert, so ACE never lets two
runs hold one test host at once, whoever registers them. A run **holds** its targets' test hosts:

- from registration until it starts, times out or is canceled (one canceled before it started never
  held them);
- once started, in any state, until its **claim** ends: its observation window, or its attribution
  window when its test **holds the host** (below). It is judged by time, as attribution is, so a
  run that errored, was canceled or was closed early still holds its hosts until then.

Registering a run, or starting one, on a host another run holds answers **409**,
`{"detail": {"message", "holders": [{"host", "run_id", "state", "until"}]}}`, with `until` null for
a run not started yet. It is a lifecycle conflict, not a refusal: no alert. Registrations and starts
on a host are decided one at a time, under the host's row lock, so two launchers racing for a host
get one run between them. `POST /api/v2/svs/runs/validate` reports it as `host_busy`.

A launcher that runs a host's tests one after another therefore waits out each run's observation
window before it registers the next. An alert caused after that, with its event time after the
next run started, is the next run's (*Without a marker: context*, below).

**A test that leaves something behind** (persistence, a scheduled task, a service) can cause alerts
after its observation window. Its test settings say so: `PUT /api/v2/svs/tests/{guid}/settings`
with `"holds_host": true` (`svs:run_manage`), or the checkbox on the test's page. Each run of it
registered afterwards holds its hosts for its whole attribution window (`holds_host` on the run).

## Run states and timers

| State | Reached by | Then |
|---|---|---|
| `created` | registration | `start`, `cancel`, or the start timeout |
| `started` | `start` | the observation window passes → `ended`; `executed` with a failure → `error`; `cancel` → `canceled` |
| `ended` | the observation window passed | waits for a person, who reviews or closes it (*Reviewing runs*) |
| `reviewed` | a person signed its result off | reviewed again after a late change |
| `canceled` | `cancel` (the launcher or a person) | `closed` when the attribution window passes, or by a person |
| `error` | `executed` reported a failure, or `start` never came | `closed` when the attribution window passes, or by a person |
| `closed` | the timers, or an analyst | final: nothing is learned from the run |

- **Cancel stops the run, not attribution.** The test may have fired anyway, so a canceled run keeps
  attributing until its attribution window passes, and is closed then.
- **A run canceled before it started** has no windows and can't have alerts: it is closed in the
  same call (`close_reason` *canceled before start*).
- **A run never started** goes to *error* `svs.runs.start_timeout_minutes` (30) after it was
  registered, and is closed at once (`close_reason` *start timeout*). It never waits in a list.
- **An ended run always waits for a person.**

`service_svs` runs the timers every `svs.runs.timer_interval_seconds` (30), on the primary node. Every
state change, by a launcher call or a timer, is a conditional update on the state it was read in,
so a timer that fires twice, or a launcher call that races a timer, changes the run once. Each one
writes a row to the run's event log (`svs_run_events`) and an INFO record carrying `svs_run`,
`svs_test`, `svs_marker`, `from_state`, `to_state` and `actor` (the caller's name, or `svs` for a
timer); `svs_run=<run uuid>` in the site's log search finds everything ACE did about a run.

## Windows

A run has two windows, both starting at `start`:

- **The observation window** is how long the run waits for its alerts before it ends. It comes from,
  in this order:
  1. **the test's settings** (`PUT /api/v2/svs/tests/{guid}/settings`, `svs:run_manage`): an
     `observation_minutes` an operator set, used as it is, with no slack and no floor, from 1 minute up
     to `ceiling_hours` (the settings also hold `holds_host`, *One run per test host*);
  2. **its expectations**: the worst-case latency of the slowest signature the test is expected to
     fire on the run's platform (and that isn't ignored), plus `slack_minutes`, within
     `floor_minutes` and `ceiling_hours`;
  3. **every hunt**, for a test without expectations (below).

  The `registered` event records which one applied (`observation_source`: `override`, `expected`
  or `all_hunts`). A hunt's worst-case latency is its `frequency` (for a cron
  frequency, the longest gap between two firings in a week) plus its `time_range` plus its `offset`;
  any other signature fires while the alert is analyzed, so the floor covers it. **A test without
  expectations yet**, which is every test until reviewed runs teach SVS what it fires, waits for the
  slowest *enabled* hunt, capped at the ceiling: the first run is the one that discovers what fires,
  so it needs the longest window, not the shortest.
- **The attribution window** is longer by `attribution_extra_hours`. An alert that arrives after the
  run ended but inside it is still attributed, as *late*.

The lengths are fixed at registration, so a run's windows don't move when hunts, expectations or
settings change while it runs.

```yaml
svs:
  runs:
    start_timeout_minutes: 30
    observation_window: {slack_minutes: 30, floor_minutes: 60, ceiling_hours: 72}
    attribution_extra_hours: 24
    max_extra_bytes: 16384
    max_targets: 16
    timer_interval_seconds: 30
```

## Refused registrations

A registration whose target is not a test host, or names a user the host doesn't list, is
**refused with 403**, with the reason for each refused target, and no run is created. It also
**creates an alert** in the `default` queue through the normal alert path: alert type
`svs - registration refused`, a detection from the built-in signature `svs_registration_refused`,
and the target host and user and the caller's name and address as observables. A launcher pointed
at a production host is something an analyst should see, so the alert is never attributed to a run,
even one live on the host it names: it stays in triage.

A launcher retrying in a loop must not flood the queue, so the alerts are **collapsed to one per
(caller, host) per clock hour**. The host is the name as the caller gave it, lower-cased: a fully
qualified name is its own host, so `win10-01.prod.example` is not folded into the alert of test host
`win10-01`. Later refusals in that hour are counted in
`svs_registration_refusals` and logged at WARNING (`caller`, `host`, `reason`, `launcher`,
`svs_test`, `alerted`), which every refusal is. A refusal is refused even when its alert can't be
created; that failure is logged at ERROR.

## Following runs

Everything about a run is readable through `GET /api/v2/svs/runs` with `svs:run_read`. The
GUI's Runs tab is a shell over the same endpoints and the same filters (`docs/SVS_API.md`, *Runs*).

- **Needs attention** (`f=needs_attention:true`) is the Runs screen's default view. It matches runs
  that:
  - ended and wait for review;
  - are in `error`;
  - were reviewed and have changed since (*What happens to the alert*, below);
  - are `reviewed` or `closed` and still hold an alert that is `OPEN` (`f=has_open_alerts:true`):
    one an analyst took before the run closed, a `partial` alert whose other detections wait for
    triage, or one closing couldn't reach yet.

  Every user starts with it as a saved filter on the screen, next to *Started* (the runs in flight).
- **A run closed because `start` never came** is not in that list. Find it with
  `f=state:closed&f=reason:start%20timeout`.
- **Each run row summarizes its result and alerts** (*Results*, below):
  - expected hits *n*/*m* (`result_hit` / `result_expected`), missing, possibly suppressed,
    candidates;
  - its alerts by marker, by context alone, and late.

  The filters `has_missing`, `has_possibly_suppressed`, `has_candidates`, `has_late` and
  `has_context_only` find the runs that have them.
- **The event log** (`GET …/runs/{run_id}/events`) is the run's history: its registration, every
  launcher call with its payload, every state change, every alert attributed to it or no longer
  attributed, and the alerts closed with it, with who did it and when. It is not a
  debugging tool. A test that didn't fire is debugged from ACE's log, by searching
  `svs_run=<run_id>` or `svs_marker=<marker>`.
- **The event feed** (`GET …/runs/events?changed_since=…`) is every run's events in one stream,
  which is what a report polls.

### In the GUI

The **SVS** entry of the navigation bar (with `svs:run_read`) opens the SVS area. Next to it is
the number of runs that need attention, when any do.

- **Runs** opens on *Needs attention*. Its filters, saved filters and share links work as on the
  alert list, and the export menu streams what the filters match.
  - A row shows the run's state and test, its targets, launcher and batch, and when it was created,
    started and ended.
  - While a run is `started`, it shows the time left in its observation window.
  - It also shows its platform, the result summary, the alerts by marker, by context and late, and
    the owner and reviewer.
  - Above the list, once a run is reviewed, is the share of missing expected signatures that were
    possibly suppressed, over every reviewed run's signed-off result. Past 50 reviewed runs or 90
    days since the first review, a share above 10% says that the suppression runs don't key by
    themselves is worth reconsidering (*Results*, below; `docs/SVS.md`, Part 3).
- **Batches** shows the same runs, one row per batch, summed: the runs by state, how many need
  attention, and the expected hits and missing signatures. The filters carry over between the two
  views, and opening a batch lists its runs.
- **Bulk actions** need `svs:run_manage`. Select runs on the page, then *Take ownership*, *Cancel*
  or *Close* them.
  - *Close* asks for a reason, which an ended run needs (*Reviewing runs*, below).
  - A run someone else owns is not touched until you confirm, in a second dialog, that you take it
    from them.
  - Afterwards the page reports what was done, what was left alone and why.
  - Review is never a bulk action.
- **Tests** lists the catalog, one row per test, in the API's one order: technique, then name
  (*Tests and their state*, above). It opens on *In the catalog*, the tests still in their
  repository; a removed test keeps its runs and is one filter away.
  - A row shows the test's technique, name and guid, its platforms and repository, and its state,
    coloured (failing in red, awaiting review and stale in amber, validated in green).
  - It also shows its latest run and latest reviewed run, each linking to the run, its number of
    runs, how many signatures are expected of it, and how many of its latest ended or reviewed runs
    missed one.
  - The tab is read-only, and its export menu streams what the filters match.
- **Test hosts** is shown only with `svs:admin`, and adds, changes and deletes test hosts (*Test
  hosts*, above).

**The run page** (`/ace/svs/runs/<run_id>`, opened from a row) is the run's review, and the screen
to watch it on while it runs. It reloads itself while the run is `created` or `started`, or while
its result is being recomputed.
- **The header** has the test, the run's state, and a timeline of its observation and attribution
  windows. Below it are the marker, targets, platform, launcher and batch (which opens the batch's runs),
  the windows' lengths, the owner, and the launcher's exit code, errors, the test's output and `extra`.
- **Its actions** need `svs:run_manage`: *Take ownership*, *Cancel* and *Close*, as in bulk, and
  *Mark reviewed* (*Review again* on a reviewed run).
  - The page lists what still stands in the way of a review: candidates to decide, context-only
    alerts to keep or mark not a test, a result being recomputed. *Mark reviewed* is enabled once
    nothing but the recompute is left.
  - Each action on a run someone else owns asks before it takes the run from them.
- **Result** is one row per signature: its status, how many alerts carry it, the result as signed
  off, what is decided about it for the test on the run's platform and by whom, and a mark for each
  of the test's last ten ended or reviewed runs on that platform, each linking to that run.
  - A decision can be undone there (*Undo*), which makes the signature a candidate again.
  - A missing YARA signature links to the files captured from the run's alerts (Signatures →
    Samples). The link is shown only with `signature:read`, so give run reviewers that permission
    as well.
- **Candidates** lists the undecided signatures and the alerts that carry them, with *Expected*,
  *Rejected*, *Ignore for this test* and, with `svs:admin`, *Ignore everywhere*
  (*Expectations and ignores*, below). A candidate the test's runs on another platform expect says
  so (*expected on linux*); that is only a hint, and the decision is still made for this platform.
- **Alerts** lists every alert the run holds, then those it no longer holds. Each shows its SVS
  status, how it is attributed, its detections, and its queue, disposition and owner.
  - *Keep*, *Not a test*, *Disassociate* and *Associate* (*Associating alerts by hand*, below) are
    on each alert.
  - Any other alert is associated by its uuid, below the list.
- **Logs** has the run's search keys, ready to copy, and a link to the site's log search when
  `svs.log_search_url` is set (*Logs*, below).
- **Comments** and the **event log**, latest event first.

**The test page** (`/ace/svs/tests/<guid>`, opened from the Tests tab, from a run's page and from the
guid on a row of the Runs tab) shows one test.
- **Its facts:** state, and the state on each platform when they differ, platforms, executor,
  repository and path, commit and content hash, runs, and expectations.
- **The catalog entry:** the description, commands (command, manual steps, cleanup), input arguments
  and dependencies.
- **Its observation window** (*Windows*, above): computed, or the minutes an operator set. With
  `svs:run_manage` it is set here, or cleared to go back to the computed window.
- **Whether its runs hold their hosts** until their attribution window ends (*One run per test
  host*, above). With `svs:run_manage` it is set here.
- **Expectations:** every decided signature, by platform, with who decided it, when, why and from
  which run. With `svs:run_manage`, *Remove* makes one a candidate again on that platform.
- **Ignores** that apply to the test: its own, which `svs:run_manage` removes, and the global ones,
  which only `svs:admin` removes.
- **Runs:** its latest 25, newest first, each linking to its run page, and a link to all of them on
  the Runs tab.

## Attribution

ACE decides which alerts a run caused by the run's marker, and failing that by its target and
window. Attribution is **per detection**: an alert is routed to the test queue (`svs.queue`) only
when every one of its detections is attributed.

### Where ACE looks for markers

| Where | What it covers |
|---|---|
| Observable values, and file observables' names | Command lines, URLs, file names a hunt or a module extracted |
| Detections' descriptions and details | A hunt or module that quotes what it matched |
| The alert's own details | A hunt's raw events, an API submission's details |
| The details of every module's analysis | Decoded or deobfuscated output, sandbox reports. The engine reads them as each module finishes, live or replayed from the analysis cache, and keeps the markers it finds on the alert (the `svs_sightings` root extension), because the details themselves are stored outside the tree. |
| File contents | The `SVS_Marker` YARA rule (*The marker*, above); its matches are part of the YARA analysis's details |

### When a marker counts

A marker **agrees** with its run when all three hold:
- the marker is a registered run's;
- the alert **involves one of the run's targets**: a `hostname` or `fqdn` observable (or one of their
  subtypes) whose short name is the target's (a fully qualified name must be the target's own when
  the test host has one), or an `ipv4` observable listed in the target test host's `ips`. The user is
  not checked: process telemetry often doesn't carry it;
- the alert's **event time** is inside the run's attribution window, from `start` to the window's
  end. The event time is the alert's (for a hunt, the query's event time), or when the alert was
  created if it has none.

A marker that doesn't agree (unknown, on another host, outside the window, or of a run that never
started) is a **mismatch**. A mismatch is never routed, and it ends attribution for the whole
alert: nothing in it is attributed, not by its other markers and not by context. A marker on a
production host is exactly what an analyst should see.

### Which detections a marker attributes

A marker attributes the detections **on its branch of the analysis tree**: the node it was found on,
every node above it and every node beneath it. A marker in the alert's own details is on the root,
which is above everything, so it attributes every detection; so is a detection on the root itself,
which every marker reaches. A marker found only inside one attachment attributes that attachment's
detections and the root's, and leaves a detection on an unrelated URL of the same email
unattributed. That alert is *partially* attributed and stays in its queue.

Siblings are not on each other's branch, and that includes a process's command line and the file it
dropped. When a hunt puts the marker on a `command_line` observable and a YARA rule fires on a
`file` observable next to it (both children of the root, say), the marker reaches neither the
other node nor its detection. If the marker is the only one in the alert, the alert gets no status
at all: it is not a mismatch, it has no banner, and it stays in its queue. So a launcher that puts
the marker only in the command line should expect file detections to be attributed only when:

- the file is found beneath the command line in the tree;
- or the marker also shows in the file, in the alert's details, or in the detection itself (its
  description or details, which is where a hunt's query results usually carry it).

### Without a marker: context

An alert with no marker at all is attributed by **context** when exactly one run could have caused
it: a run whose window covers the alert's event time and one of whose targets the alert involves.
Context has no per-detection signal, so it attributes every detection. When several runs' windows
cover the alert on its host, the run that started last claims it, as long as every other one's claim
on the host ended before that run started (*One run per test host*, above): a test that leaves
nothing behind causes nothing after its claim ends, so the alert is the latest run's. Each earlier
run's own alerts keep its window: an alert whose event time is inside the earlier run's window and
before the later run started is still the earlier run's, *late* if it is after its observation
window. When the claims overlap, which only runs registered before one run per host was enforced
can do, nothing is attributed and a WARNING names them (`candidate_runs`): attributing to the wrong
run would teach the wrong expectation.

An alert with no detections is never attributed.

### What happens to the alert

| Status | When | Where the alert goes | Tags |
|---|---|---|---|
| `test` | every detection is attributed by a marker | `svs.queue` | `svs_test` |
| `test?` | attributed by context | `svs.queue` | `svs_test` |
| `partial` | some detections are attributed | stays in its queue | |
| `mismatch` | a marker doesn't agree | stays in its queue | `svs:marker_mismatch`, and a detection from the built-in signature `svs_marker_mismatch` naming the marker and why |

- **When.** The `svs_marker` alert router (`saq/svs/routing.py`, an `alert_routers` entry at priority
  100, ahead of the detection-queue router) judges every alert as it is created, and again after
  every correlation pass of an existing alert, which catches markers that only analysis finds in a
  hunt alert. A marker that agrees overrides any configured queue: a hunt's, a submission's, or a
  YARA rule's `queue` meta.
- **Moving an existing alert.** After analysis, ACE moves an alert only while it is open and nobody
  has taken it; one an analyst owns keeps its place and is still attributed. An alert the router
  routed that is no longer fully attributed (a later pass found a detection the run doesn't reach)
  goes back to the queue it came from.
- **Tags and the mismatch detection** come from the `svs_alert_tagger` module, which runs in the
  correlation mode's post-analysis and judges the alert the same way. A router never changes the
  tree. A mismatch is never taken back; `svs_test` is removed when the alert stops being fully
  attributed.
- **Late.** An alert whose event time is after the run's observation window, but inside its
  attribution window, is attributed and marked *late*.
- **After review.** An attribution added to or removed from a run that was already reviewed (a late
  alert, or a later analysis pass) marks the run *changed since review*, which puts it back in
  *Needs attention*.
- **Verdicts.** An alert attributed to a run that isn't reviewed has no detection verdicts, and its
  YARA hits are not captured as samples, whatever its disposition (`docs/SVS.md`, Part 1). That holds
  for a `partial` alert too: its real detections get their verdicts once the run is reviewed, and
  never if the run is closed.

Every attribution is a row of `svs_attributions`: the run, the alert uuid, the detection's
`content_hash` (the key of its `detection_points` row and its verdict), the confidence (`marker` or
`context`), *late*, and where the marker was found. A row that stops applying is kept, marked
removed, and a row a person removed is never added again by the router. Each change is also an
event in the run's event log (`attributed`, `attribution_removed`), once per run and alert.

The status is never stored: it is derived from these rows whenever an alert is read, as
`svs_status` and `svs_runs` in `GET /api/v2/alerts` (`docs/SVS_API.md`, *Alerts*). There an alert
is `test` or `test?` when every one of its `detection_points` rows has an attribution that holds,
to any run, `partial` when some have, and `mismatch` when it has none and carries the
`svs:marker_mismatch` tag.

### Cost

None of this runs while no run is registered or inside its attribution window: each process asks
the database at most every `gate_cache_seconds` whether one is, and scans nothing while none is.
Registering a run opens the gate before its test fires. A marker is looked up in the database the
first time a process sees it; only runs that have started are kept in each process's cache, since
nothing attribution needs of them changes afterwards, and a marker the cache doesn't have always
goes to the database.

```yaml
svs:
  attribution:
    gate_cache_seconds: 5
    marker_cache_size: 1024
    max_sightings: 200   # markers from module output kept per alert
```

### Logs

A record about a run carries its `svs_run`, `svs_test` and `svs_marker`; a sighting of a marker no
run has carries only `svs_marker`:

| Record | Level | Fields |
|---|---|---|
| `svs marker … in alert …` | INFO; a mismatch at WARNING | `alert_uuid`, `scan_point`, `result` (`attributed`, `unknown`, `other host`, `outside window`), `stage` |
| `svs router decision on alert …` | INFO | `alert_uuid`, `stage`, `decision` (`routed`, `partial`, `mismatch`, `moved back`, `held (manual)`, `not moved because owned`/`closed`), `queue`, `confidence` |
| `svs context attribution of alert … refused` | WARNING | `alert_uuid`, `candidate_runs` (no `svs_run`) |
| `svs attribution written` / `removed` | INFO | `alert_uuid`, `detection`, `confidence`, `late`, `source` |
| `svs run … changed since review` | INFO | `alert_uuid` |
| `svs run …: n alerts closed as SIMULATED` | INFO | `alert_uuids`, `left_alone` (taken by an analyst, or dispositioned, meanwhile), `late`, `actor` |
| `AUDIT: svs alert associated with a run` / `disassociated from a run` / `svs context attribution kept` | INFO | `alert_uuid`, `actor`, `actor_user_id`, and `reason`, `late` or `not_a_test` (*Associating alerts by hand*, below) |

`svs.log_search_url` makes the run page's *Logs* section a link to the site's own log search. ACE
never queries it. It is an `http` or `https` URL in which `{run_uuid}`, `{marker}`, `{test_guid}`,
`{earliest}` and `{latest}` are replaced, each URL-encoded. `{earliest}` and `{latest}` are epoch
seconds:
- `{earliest}` is when the run started (or was registered, if it never started);
- `{latest}` is when its attribution window ends (or when it was canceled or closed, if it never
  got one), or now when that is still to come.

Any other name in braces fails the config, and a literal brace is written `{{` or `}}`. For example:

```yaml
svs:
  log_search_url: https://splunk.example/en-US/app/search/search?q=search%20svs_run%3D{run_uuid}&earliest={earliest}&latest={latest}
```

## Test alerts in the alert list and on the alert page

Analysts see an alert's status (*What happens to the alert*, above) where they triage it.

- **In the alert list**, the status is shown after the alert's description as text with a flask
  icon: `TEST`, `TEST?`, `PARTIAL TEST` or `MARKER MISMATCH`, the last in red. It is not a badge
  (badges are tags and dispositions). With `svs:run_read` it links to the latest run the alert is
  attributed to.
- **On the alert page**, the status is a banner above the alert's summary. It says what the status
  means and what to do, and names the alert's runs: test, short run id and state, each a link with
  `svs:run_read`.
  - A mismatch banner is red. It names each disagreeing marker, why it disagrees, and the run the
    marker belongs to when there is one.
  - On a `PARTIAL TEST` alert, the detections attributed to a run are greyed out, in the analysis
    tree and in the Detection Chains card, so the analyst triages the others.
- **Giving a test alert back.** With `alert:write`, the banner has *Disassociate from run* and, on a
  `TEST?` alert, *Not a test*.
  - Each asks for a reason, then disassociates the alert from every run that holds it (*Associating
    alerts by hand*, below), and the page reloads.
  - A `SIMULATED` alert comes back `OPEN`, and an open alert nobody else has taken goes back to the
    queue SVS took it from.
  - The run-scoped actions on the run page need `svs:run_manage`. These need only `alert:write`,
    because they are an analyst's correction of an alert they triage, in the direction that makes it
    *more* visible.
- **The disposition dialogs** say why a `SIMULATED` alert is left alone: on its page, *"Part of SVS
  test run … To treat this as a real alert, use Disassociate from run."*. A selection on the alert
  list says how many of the selected alerts are left alone and why; Save is disabled when nothing
  would change. A `SIMULATED` alert is never counted as someone else's to take, although the
  automation user owns it.

## Associating alerts by hand

A person with `svs:run_manage` corrects what the router decided, one alert and one run at a time:
`POST /api/v2/svs/runs/{run_id}/alerts/{alert_uuid}/{action}`, with an optional `{"reason"}`
(`docs/SVS_API.md`, *Attributions*). From the alert's side, an analyst with `alert:write` runs
`disassociate` or `not-a-test` for every run that holds the alert at once: `POST
/api/v2/alerts/{alert_uuid}/svs/disassociate|not-a-test` (`docs/SVS_API.md`, *An alert's SVS
status*), which is what the alert page's banner calls. Each change is recorded in the run's event log and as an AUDIT
record with who made it, marks the run's result stale (*Results*, below), and marks a reviewed run
changed since review. Every change can be undone by the opposite one.

| Action | What it does |
|---|---|
| `associate` | Attributes every detection of the alert to the run, by hand (`source` `manual`). A person's association is certain, so it counts as a marker would: the alert becomes `test`. *Late* is judged on the alert's event time, as the router judges it. Refused for a run that never started, and for an alert without detections. |
| `disassociate` | Removes the alert's attributions to the run, recording the person and the reason. The router never attributes the alert to that run again, for any of its detections, even ones a later analysis pass finds. |
| `not-a-test` | `disassociate` for a `TEST?` alert, one the run holds by context alone (refused otherwise); the reason is *not a test*. |
| `keep` | Confirms a `TEST?` alert's context attributions: a person says it is the run's. Run review asks for every context-only alert to be kept or marked not a test. |

- **Moving the alert.** An alert that `associate` makes fully attributed moves to the test queue.
  One that `disassociate` leaves not fully attributed goes back to the queue SVS took it from: the
  queue before its latest move, when that move was into the test queue by the router or by a person
  here. An alert that was submitted straight into the test queue stays there. As with the router, an
  alert moves only while it is `OPEN` and nobody else has taken it; the response says whether it
  moved.
- **Giving a `SIMULATED` alert back.** Disassociating a `SIMULATED` alert that is then no longer
  fully attributed sets it back to `OPEN`. The automation user, which set `SIMULATED` and owns it,
  writes it, with the comment *disassociated from SVS test run … by …*, and gives it up, so the
  alert is unowned and analysts triage it like any other alert. An alert still fully attributed to another run keeps its queue and disposition.
  An alert disassociated while its run is closed or reviewed is never left `SIMULATED` without a
  run: closing checks again that each alert is fully attributed under the alert's row lock, which
  disassociating takes too, so either the alert stays `OPEN` or it is given back.
- **A queue set by hand is held.** Every move made here is recorded with the router name
  `svs_manual`. While that is the alert's latest move, the `svs_marker` router still attributes the
  alert on each correlation pass but keeps it where it is (`held (manual)` in its decision log). A
  router of lower priority gets no turn either. So a disassociated alert isn't moved back by
  re-analysis, even when a marker for another run turns up, and an associated one isn't moved out.
- **A marker that disagrees** with its run still flags a hand-associated alert `svs:marker_mismatch`,
  but its attribution stays and so does its status (`test`): the person's association wins.

## Results

When a run ends, ACE works out what it found: one row per signature in `svs_run_results`,
readable at `GET /api/v2/svs/runs/{run_id}/results` and across runs at `GET …/runs/results`
(`docs/SVS_API.md`, *Results*). What *fired* is the run's attributions that hold, by the signature
of each attributed detection. Against what is decided for the test (*Expectations and ignores*,
below), each signature is:

| Status | When |
|---|---|
| `hit` | It is expected, and it fired |
| `missing` | It is expected, and it did not fire |
| `possibly_suppressed` | It is missing, it is a hunt with a `suppression` period, and the hunter dropped a match of it during the run for that suppression, or (without `group_by`) the hunt alerted within that period before the run's window closed (below) |
| `cleanup` | It fired only during the test's cleanup, and it isn't expected (*Cleanup*, above) |
| `candidate` | It fired, and nobody has decided about it yet |
| `rejected` | It fired, and it was rejected for the test |
| `ignored` | It fired, and it is ignored for the test or globally |

- **Precedence.** A signature that fired only during the cleanup is `cleanup`, or `missing` when it
  is expected. Any other that fired is `ignored` before anything else, then `hit`, then `rejected`,
  then `candidate`. An ignored signature is never missing either.
- **Signatures that never count.** `generic`, `legacy` and `yara_rule_match` stand for many
  unrelated detections (no specific signature, detections from before signatures were recorded, a
  YARA rule without a `uuid`). `observable_flagged_for_detection` fires on whatever analysts
  flagged, so flagging a value would change results. The SVS built-ins are about runs and are never
  attributed to one.
- **Each row also holds:**
  - how many of the run's alerts carry the signature;
  - whether every attribution of it was *late*, or by *context* alone;
  - the signature's family and name;
  - the content hash of the rule itself as it was when the result was computed. A missing row has
    one too: coverage uses it to tell when an expected rule changed.
- **Possibly suppressed.**
  - **A hunt with `group_by`** suppresses each group on its own, inside its query results. During a
    run, a group on one of the run's test hosts is suppressed under a key of the run's own (*Hunt
    suppression during runs*, below), so it drops a match there only once that run's own first
    match alerted, or when the runs couldn't be looked up. When it drops a match for its suppression
    and the match's event time falls in a run's attribution
    window, on one of the run's test hosts (its `hostname`, `fqdn` or test-host `ipv4` observables,
    as attribution reads them), the hunter records it in `svs_suppressed_matches`: one row per run
    and hunt, for the first such match, and the run's result goes stale. The match goes to the run
    context attribution would give it to, so a run's test never counts against the run before it
    on the host, or to each of them when their claims overlap (runs registered before claims were
    enforced). The hunt is `possibly_suppressed` in that run's result exactly
    when it has such a row, so that is not a guess, and no alert is named: the hunt's latest alert
    may have been another group's. Nothing is recorded while no run is open, as for alerts, and a
    failure to record is logged at ERROR and keeps the suppression.
  - **Any other hunt** suppresses as a whole and doesn't run at all while suppressed, so there is no
    match to record. A hunt checks its `suppression` each time it runs, and the run that would have
    caught the test comes up to its latency after the start. So ACE looks for an alert carrying a
    detection of the hunt, inserted from `suppression` before the run started until the run ended,
    and not attributed to this run. The latest one is named (`suppressing_alert_uuid`). Only hunts in
    correlation mode put their detection on their alerts, so only theirs can be found.
  - For a hunt with `dedup_key` and no `group_by` that answer is imprecise: that alert may have been
    for another key. The row says so (`suppression_imprecise`).
  - What runs don't key by themselves is revisited once reviewed runs show how often a missing
    signature was possibly suppressed (`docs/SVS.md`, Part 3).
    `GET /api/v2/svs/runs/suppression-share` and the Runs tab show that share.
- **Kept current.** The result is computed when the run ends. Anything that would change it marks
  it stale and the timers recompute it on their next pass (`svs.runs.timer_interval_seconds`):
  - an attribution added or removed, a late alert for one;
  - a decision about the test: an expectation, an ignore of the test, or any global ignore.

  Only `ended` and `reviewed` runs are recomputed. The API's `stale` says a run's result is about
  to change. A signature that leaves the result is deleted from it, unless the row holds the result
  as reviewed, when only its live `status` becomes null.
- **The event log** gets a `result_computed` event when the counts per status change.

| Record | Level | Fields |
|---|---|---|
| `svs run …: hunt … suppressed a match for group_value …` | INFO, the first per run and hunt | `hunt_uuid`, `group_value` |
| `svs run … result computed: …` | INFO, plus DEBUG per signature | `counts` (per status) |
| `svs run … is missing expected signature …` | INFO, once each time a signature becomes missing | `signature_uuid`, `signature_family`, `possibly_suppressed`, `suppressing_alert_uuid`, `suppression_imprecise` |

### Hunt suppression during runs

A hunt with a `suppression` period stays silent for a group after it alerted on it, which would
make a test re-run inside that period read *missing*. So while a run is open, a hunt with `group_by`
keys the suppression of each group by the run (`QueryHunt.key_suppression`):

- **Which groups.** A group whose alert involves one of the run's test hosts (its `hostname`, `fqdn`
  or test host `ipv4` observables, as attribution reads them) with its event time inside the run's
  attribution window. Several runs' windows can cover it: the run context attribution would choose
  is the one (*Without a marker: context*, above).
- **What it does.** The group's suppression is recorded and checked under a key of its own for the
  run (`svs_run:<run uuid>:<group value>`), so each run's first match alerts and the rest of that
  run's are suppressed as usual. An alert before the run (production, or another run) doesn't hide
  the test, and the test doesn't suppress the group for production or for the next run.
- **What it doesn't reach.** A hunt without `group_by`, whose suppression stops the whole hunt from
  running, and whose catch-up after suppression must not lose production alerts; a group whose
  alert doesn't carry the test host (a `group_by` field other than the host, with no host
  observable); and `dedup_key`. Those can still hide a test. For a hunt without `group_by` the
  result reads *possibly suppressed* (*Results*, above); a dropped match of a group that doesn't
  carry the test host isn't recorded for the run either, so the hunt reads *missing*.
- **Cost.** Nothing while no run is open (the attribution gate, *Cost*, above); otherwise one query
  per hunt execution, and one more when it drops a match, to record it (*Results*, above).
- **Logs.** Each group keyed by a run is logged at INFO, `hunt … group_value …: suppression keyed by
  svs run …`, with the run's `svs_run`, `svs_test` and `svs_marker`, `hunt_uuid` and `group_value`.
  A failure to look the runs up is logged at ERROR, and the hunt suppresses by group as before.

## Expectations and ignores

What a run is judged by is decided per test and platform, by a person, and learned from runs rather
than from the techniques a test declares (`docs/SVS.md`, Part 3, *Expectations*).

- **An expectation** is a signature a run of the test on a platform should fire (`expected`), or
  one that fires there but isn't what the test is about (`rejected`). A rejected signature is
  remembered and isn't proposed again for that platform. Anything else a run fires is a `candidate`
  in its result: there is no stored candidate, so nothing goes stale.
  - **A run is judged by its own platform's decisions only** (every run has one platform,
    *Registering a run*). A test that supports several platforms runs different commands on each,
    and so fires different signatures: what a linux run taught isn't expected of a windows run.
  - Decide with `PUT /api/v2/svs/tests/{guid}/expectations/{platform}/{signature_uuid}` `{state,
    reason?, run_id?}` (`svs:run_manage`). The platform has to be one the test supports (its
    `supported_platforms` as platform slugs, so `iaas:aws` is `iaas`), or the answer is 422.
  - A `run_id` (a run of that test, on that platform, or 422) says which run's result the decision
    was made from. That run's event log records it (`candidate_decision`).
  - Removing a decision (`DELETE`, same path) makes the signature a candidate again the next time a
    run on that platform fires it. Nothing removes an expectation automatically: a flaky signature
    shows up in the run history.
  - In the GUI, decisions are made among a run's candidates on its page, and undone there or on the
    test's page (*In the GUI*, above).
- **An ignore** marks a signature as noise during runs on every platform, such as the launcher's own
  WinRM or remoting:
  - for one test: `PUT …/tests/{guid}/ignores/{signature_uuid}`, `svs:run_manage`;
  - for every test: `PUT /api/v2/svs/ignores/global/{signature_uuid}`, `svs:admin`, because it
    changes every test's results.
- **Every change** is an AUDIT record with who made it, and marks the results of the affected runs
  stale: a decision, the test's runs on its platform; an ignore, all the test's runs (or every
  test's).
- **Expected signatures set the window.** A new run of a test with expectations on its platform
  waits for the slowest of them (*Windows*, above).

## Reviewing runs

A person with `svs:run_manage` acts on runs through `POST /api/v2/svs/runs/…` (`docs/SVS_API.md`,
*Run actions*). Every action is in the run's event log and an AUDIT or transition record with who
took it.

- **Ownership** works as it does for alerts. A run someone else owns is changed only when the
  person confirmed taking it from them (`confirmed_takes`), and it then becomes theirs; a run whose
  owner's account is disabled or gone counts as nobody's. *Take ownership* (`bulk/take-ownership`)
  does only that. Reviewing a run also takes it when nobody owns it.
- **Cancel** (`bulk/cancel`) is the launcher's cancel, by a person: a created or started run is
  canceled, and one that never started is closed at once.
- **Close** (`bulk/close`) discards an ended, canceled or failed run: its fully attributed open
  alerts become `SIMULATED`, and nothing is learned from it. An ended run waited for a review, so
  closing it instead needs a reason.
- **Review** (`{run_id}/review`, never a bulk action) signs an ended run's result off. It needs:
  - the result to be current (not `stale`);
  - every candidate decided (expected or rejected, *Expectations and ignores*);
  - every context-only (`TEST?`) alert kept or marked not a test (*Associating alerts by hand*).

  The answer is 409 with what is still in the way. When it goes through, in this order:
  1. the run is committed as `reviewed`, with its reviewer, and its live result is copied to the
     result as signed off (`reviewed_*`);
  2. its fully attributed open alerts nobody has taken become `SIMULATED` (comment *reviewed with
     SVS test run … by …*). The run is reviewed by then, so their YARA hits are captured as TP
     samples (`docs/SVS_SAMPLES.md`) and their detections get verdicts;
  3. the detections of signatures ignored for the test (launcher noise) get an FP verdict from the
     reviewer, unless someone already gave them one.

  A failure after step 1 keeps the review; reviewing again finishes the job.
- **Review again.** A late alert, a manual association or a disassociation after the review marks
  the run *changed since review* and puts it back in *Needs attention*. The late alert stays open
  until the run is reviewed again. A re-review has the same preconditions, replaces what was signed
  off, closes the alerts that arrived since, and clears the flag. The event log keeps each
  review's counts.
- **Comments** (`{run_id}/comments`) are a person's notes on a run; only the author changes or
  deletes one.

Closing never writes FP verdicts: an alert attributed to a run that is not reviewed has no
verdicts at all, so they would never count.

## Test alerts and `SIMULATED`

When a run is reviewed or closed, SVS gives every alert fully attributed to it the disposition
**`SIMULATED`**, both when a person reviews it and when it is closed (*Reviewing runs*).

- **Which alerts.** Those whose every detection is attributed (`svs_status` `test` or `test?`), to
  this run or to it and another, that are still `OPEN` and that nobody has taken (the automation
  user counts as nobody). A `partial` alert stays open for analysts to triage its other
  detections, and an alert an analyst took stays theirs; either keeps the run in *Needs attention*
  until it is dispositioned.
- **When.** As the run closes, whoever closes it, and afterwards: an alert attributed to a run that
  is already closed (a hunt reports late, inside the attribution window) is closed by the timers'
  next pass, `svs.runs.timer_interval_seconds`. A failure to close them never undoes the close; the
  next pass closes them too.
- **What it records.** The automation user dispositions the alert with the comment *closed with SVS
  test run …*, the run's event log gets an `alerts_closed` event listing them, and an INFO record
  (*Logs*, above) lists them and any left alone.
- **Nothing is learned from them.** The run isn't reviewed, so their detections have no verdicts
  and their YARA hits are not captured (`docs/SVS.md`, Part 1 and Part 2).

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
  disassociated from its run (*Associating alerts by hand*, above), which gives it back to analysts
  as `OPEN`.
- **It is never reset or re-analyzed, and gets no new observables.** Each of these refuses a
  frozen alert with *"alert … is SIMULATED, a disposition only ACE sets: it can't be reset,
  re-analyzed or given new observables"*:
  - `ace alert reset` and `ace alert analyze` / `reload` (the alert is skipped and the error logged);
  - the GUI's *Analyze*, uploading a file to the alert, and *Add observable*;
  - the observable actions, `POST /api/v2/alerts/{uuid}/observables/{uuid}/collect-file`, `render`,
    `crawl` and `check-for-clickers` (409), which the alert page calls;
  - `POST /api/v2/alerts/bulk-add-observable` (a per-alert failure).
- **Its verdict chips are read-only.** The run review owns those verdicts (`docs/SVS.md`, Part 1).

Tags, comments and ownership changes still work on a frozen alert.

### Test alerts in search

Test-run alerts are routed to their own queue, `svs.queue` (default `svs`; see *Attribution*).
Alert search and *similar alerts* leave that queue out whenever a request says
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
