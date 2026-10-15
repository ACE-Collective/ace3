# SVS test runs

SVS runs Atomic Red Team tests: an outside launcher registers a **run** with ACE, the test fires on a
test host, and the alerts it causes are attributed to the run instead of being triaged as real
incidents. Reviewing a run teaches SVS which signatures detect which techniques (`docs/SVS.md`,
Part 3).

This document covers how runs work in ACE and how to operate them. It grows with phase 4. Today it
covers the test hosts, the Atomic Red Team catalog, how a launcher registers and drives a run, the
run states and timers, refused registrations, how alerts are attributed to runs and routed to the
test queue, what happens to a test run's alerts once SVS closes them, and how search treats them.
Closing a run's alerts, reviewing runs and the SVS screens arrive later in phase 4. The design and
its reasoning are in `docs/SVS.md`; the API's data dictionary is `docs/SVS_API.md`.

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

## Registering a run

ACE never runs a test. A **launcher** outside ACE (a script around `Invoke-AtomicTest`, a CI job, a
person with `curl`) drives each run through `/api/v2/svs/runs` with an API key holding
`svs:run_register`:

| Call | Does |
|---|---|
| `POST /api/v2/svs/runs/` | Registers a run for one catalog test against one or more test hosts. Answers 201 with `run_id` and the run's **marker**. |
| `POST /api/v2/svs/runs/{run_id}/start` | The test is about to fire: the windows start now. |
| `POST /api/v2/svs/runs/{run_id}/executed` | Optional. How the test executed: a non-zero `exit_code` or an `error` moves the run to *error*. |
| `POST /api/v2/svs/runs/{run_id}/cancel` | Stops the run. |

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
- **`launcher`** names the launcher; **`batch_id`** is a label shared by runs registered together;
  **`extra`** is any JSON object the launcher wants kept with the run, at most
  `svs.runs.max_extra_bytes` (16 KiB) serialized. It is stored and shown on the run page.
- A call that doesn't apply to the run's state (starting a run twice, `executed` before `start`)
  answers 409 with the run's current state. Each call, accepted or not, is in the run's event log
  with its payload.

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

## Run states and timers

| State | Reached by | Then |
|---|---|---|
| `created` | registration | `start`, `cancel`, or the start timeout |
| `started` | `start` | the observation window passes → `ended`; `executed` with a failure → `error`; `cancel` → `canceled` |
| `ended` | the observation window passed | waits for a person, who reviews or closes it (later in phase 4) |
| `reviewed` | an analyst signed it off | (later in phase 4) |
| `canceled` | `cancel` | `closed` when the attribution window passes |
| `error` | `executed` reported a failure, or `start` never came | `closed` when the attribution window passes |
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

- **The observation window** is how long the run waits for its alerts before it ends: the worst-case
  latency of the slowest signature the test is expected to fire, plus `slack_minutes`, within
  `floor_minutes` and `ceiling_hours`. A hunt's worst-case latency is its `frequency` (for a cron
  frequency, the longest gap between two firings in a week) plus its `time_range` plus its `offset`;
  any other signature fires while the alert is analyzed, so the floor covers it. **A test without
  expectations yet**, which is every test until reviewed runs teach SVS what it fires, waits for the
  slowest *enabled* hunt, capped at the ceiling: the first run is the one that discovers what fires,
  so it needs the longest window, not the shortest.
- **The attribution window** is longer by `attribution_extra_hours`. An alert that arrives after the
  run ended but inside it is still attributed, as *late*.

The lengths are fixed at registration, so a run's windows don't move when hunts change while it
runs. A per-test window that overrides the computed one is not available yet.

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
at a production host is something an analyst should see.

A launcher retrying in a loop must not flood the queue, so the alerts are **collapsed to one per
(caller, host) per clock hour**. Later refusals in that hour are counted in
`svs_registration_refusals` and logged at WARNING (`caller`, `host`, `reason`, `launcher`,
`svs_test`, `alerted`), which every refusal is. A refusal is refused even when its alert can't be
created; that failure is logged at ERROR.

## Following runs

Everything about a run is readable through `GET /api/v2/svs/runs` with `svs:run_read`. The
GUI's Runs tab, which comes later in phase 4, is a shell over the same endpoints and the same
filters (`docs/SVS_API.md`, *Runs*).

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
- **The event log** (`GET …/runs/{run_id}/events`) is the run's history: its registration, every
  launcher call with its payload, every state change, every alert attributed to it or no longer
  attributed, and the alerts closed with it, with who did it and when. It is not a
  debugging tool. A test that didn't fire is debugged from ACE's log, by searching
  `svs_run=<run_id>` or `svs_marker=<marker>`.
- **The event feed** (`GET …/runs/events?changed_since=…`) is every run's events in one stream,
  which is what a report polls.

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

### Without a marker: context

An alert with no marker at all is attributed by **context** when exactly one run could have caused
it: a run whose window covers the alert's event time and one of whose targets the alert involves.
Context has no per-detection signal, so it attributes every detection. When two runs could claim
the alert (overlapping runs on one host), nothing is attributed and a WARNING names both
(`candidate_runs`): attributing to the wrong run would teach the wrong expectation.

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
| `svs router decision on alert …` | INFO | `alert_uuid`, `stage`, `decision` (`routed`, `partial`, `mismatch`, `moved back`, `not moved because owned`/`closed`), `queue`, `confidence` |
| `svs context attribution of alert … refused` | WARNING | `alert_uuid`, `candidate_runs` (no `svs_run`) |
| `svs attribution written` / `removed` | INFO | `alert_uuid`, `detection`, `confidence`, `late`, `source` |
| `svs run … changed since review` | INFO | `alert_uuid` |
| `svs run …: n alerts closed as SIMULATED` | INFO | `alert_uuids`, `left_alone` (taken by an analyst, or dispositioned, meanwhile), `late`, `actor` |

## Test alerts and `SIMULATED`

When a run is reviewed or closed, SVS gives every alert fully attributed to it the disposition
**`SIMULATED`**. Closing does so now; the run review, later in phase 4, will too.

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
