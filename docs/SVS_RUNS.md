# SVS test runs

SVS runs Atomic Red Team tests: an outside launcher registers a **run** with ACE, the test fires on a
test host, and the alerts it causes are attributed to the run instead of being triaged as real
incidents. Reviewing a run teaches SVS which signatures detect which techniques (`docs/SVS.md`,
Part 3).

This document covers how runs work in ACE and how to operate them. It grows with phase 4. Today it
covers what happens to a test run's alerts once SVS closes them, and how search treats them. The
design and its reasoning are in `docs/SVS.md`.

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
