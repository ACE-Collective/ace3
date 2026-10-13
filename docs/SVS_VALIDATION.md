# SVS YARA validation

A change to YARA rules is checked against the samples analysts have graded (`docs/SVS_SAMPLES.md`):
every stored sample is scanned with the rules as they are on the base commit and as they are on the
head commit, and the two scans are compared against the labels. A file graded as a real hit that
stops matching is a **regression**; a file graded as a false positive that starts matching is a
**new false positive**. The report warns and never blocks.

This document covers how a validation runs and what it reports. The design and its reasoning are in
`docs/SVS.md`, Part 2, *Validation* and *Report and baseline*.

The signature repository's CI requests a validation through the API (`validate-yara`, below);
`service_svs` runs it from a queue and stores the report, which CI summarizes on the pull request
with a link to ACE. `ace svs yara validate` runs one from the command line instead, synchronously,
storing nothing. The reports are read under *Signatures → Validations*
([In the GUI](#in-the-gui)).

## Which rules are validated

A validation names a **repository**: a `git_repo_<name>` section listed in `svs.yara.repositories`.
SVS uses that section's `git_url`, `ssh_key_path` and `branch`, and works out from
`service_yara.signature_dir` which of the repository's directories the yara service loads
(`saq/svs/yara/layout.py`). The yara service loads every directory directly inside
`signature_dir` as one namespace, and only the `.yar`/`.yara` files directly inside a namespace
directory. A repository can feed it in one of two ways:

- **contained**: `signature_dir` is the repository's `local_path` or lies inside it. Every
  directory at that path in a commit is a namespace, so a namespace a change adds is validated with
  it.
- **linked**: entries of `signature_dir` are, or are symlinks to, directories inside `local_path`.
  Each of those entries is a namespace, named after the entry, read from the same path in each
  commit.

A repository that feeds neither way holds no rules the yara service loads, and validating it is an
error. `ace svs yara layout` prints what SVS derived for each configured repository.

## Requesting a validation (CI)

The repository's CI calls ACE; ACE never talks to the forge. The CI holds an API key of a dedicated
automation user that has only `svs:validate`, so a leaked key can request validations and read
their counts, and nothing else: no sample, file name or alert leaves ACE through it.

```bash
ace user add svs-ci svs-ci@example.com
ace perm user add svs-ci svs:validate
ace user add-api-key svs-ci --scope svs:validate --name ci    # printed once: the CI's secret
```

A scoped key can do only what both its scope and its user's grants allow, so the key is limited to
`svs:validate` even if the user later gains more.

`validate-yara` (`lib/signature_validator`, next to `validate-hunt`) does the rest from a checkout
of the rule repository:

1. It works out the commits: `--head` (default `HEAD`) and `--base` (default: the merge base of the
   head and `origin/<--target-branch>`), both as full commit ids, and the head's `--branch`.
2. It requests the validation (`POST /api/v2/svs/yara/validations`). An identical request (same
   repository and commits) shares the validation that is queued or running, or gets the completed
   one back while the samples, their labels and the validation code are unchanged, so a re-run CI
   job does not rescan.
3. It polls the status until the validation completes or fails, or `--timeout` (default 3600
   seconds) passes.
4. It prints a Markdown summary, and writes it to `--summary-file`: the counts, the regressions and
   new false positives by rule, the files that do not compile, and the link to the report in ACE
   ([In the GUI](#in-the-gui)).

Validation warns and never blocks. `validate-yara` exits 0 whatever the validation found, also when
it failed or is still running at the timeout; it exits 2 only when it could not ask (a missing
argument, git, the connection, or a key ACE refused), so a broken setup shows.

It takes the same connection arguments and environment as `validate-hunt` (`ACE_API_HOST`,
`ACE_UI_HOST`, `ACE_API_KEY`, `ACE_CA_BUNDLE`, the PEM or PKCS#12 client certificate), plus
`ACE_SVS_REPOSITORY` for `--repository`.

An example GitHub Actions workflow for the rule repository:

```yaml
name: SVS YARA validation
on:
  pull_request:
    paths: ["yara/**"]

jobs:
  validate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0              # the merge base must be in the clone
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install "git+https://github.com/ACE-Collective/ace3.git#subdirectory=lib/signature_validator"
      - name: Validate
        env:
          ACE_API_HOST: ace.example.com:443
          ACE_UI_HOST: ace.example.com:443
          ACE_API_KEY: ${{ secrets.ACE_SVS_VALIDATE_KEY }}
          ACE_SVS_REPOSITORY: signatures
        # the checkout is a merge commit; validate the pull request's own head
        run: |
          validate-yara --head "${{ github.event.pull_request.head.sha }}" \
            --pr-url "${{ github.event.pull_request.html_url }}" --summary-file svs-summary.md
          cat svs-summary.md >> "$GITHUB_STEP_SUMMARY"
      - name: Comment
        if: hashFiles('svs-summary.md') != ''
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh pr comment "${{ github.event.pull_request.number }}" --edit-last --body-file svs-summary.md \
            || gh pr comment "${{ github.event.pull_request.number }}" --body-file svs-summary.md
```

The job passes whatever the validation found; the comment and the job summary are the signal. It
fails only when `validate-yara` could not ask, which is worth fixing. SVS's YARA validation and
`validate-hunt` (`docs/HUNTS.md`, *Validation API*) go the same direction, the repository's CI
calling ACE, but they are separate systems.

## The svs service

`service_svs` (`saq/svs/service.py`, its own `svs` container) runs the queue
(`saq/svs/validations.py`). It runs `svs.yara.max_concurrent_validations` workers (one by default)
on the primary node only; on any other node it stays idle.

- **The queue.** A request is a row in `svs_validations`, `queued`. A worker claims the oldest one
  with a conditional UPDATE that repeats the condition, so two workers never both take it, and
  holds a **lease** on it: it renews a heartbeat every `heartbeat_interval_seconds` while it runs.
  A validation whose worker stopped heartbeating for `lease_seconds` (the node died, say) is taken
  over by another worker; after `max_attempts` claims it is `failed` instead. The lease times come
  from the database clock.
- **Running.** The worker runs the replay (below) with the samples retired at that moment, and
  stores the report: its counts, the commits' compile results, the rules added, removed and changed,
  the skipped samples and timings in `svs_validations`, and each listed pair, with the sample's label
  as it was when the validation ran, in `svs_validation_results`. A validation that could not run is
  `failed` with the reason (the message of the replay's error; anything unexpected is logged and
  reads "internal error").
- **The cache.** A completed validation records the **corpus version** and the **engine
  fingerprint** it ran with. The corpus version is a digest of the latest change time and the row
  count of the stored captures, the verdict history, the retirements, the sample deletions and the
  alerts the captures come from; the counts catch what bumps no change time (a cleared verdict, a
  deleted alert). The engine fingerprint covers the replay's code, the YARA library versions, the
  disposition classification, the per-file scan timeout and the repository's layout. A request for
  the same commits is answered from a completed validation while both are unchanged; a failed one is
  never reused.
- **Stopping.** When the service stops, a worker cancels its sandboxed scan (the sandbox kills
  everything the scan started) and returns its validation to the queue without counting the
  attempt. A worker that loses its lease cancels its scan and drops its result.
- **Retention.** `ace svs yara prune` (daily, `etc/cron/daily/svs-validations-prune`, primary node)
  removes the validations that finished more than `svs.yara.retention_days` ago, with their rows.
  Deleting a sample (`docs/SVS_SAMPLES.md`, *Actions*) removes its rows from every report.

## How a validation runs

`run_replay()` (`saq/svs/yara/replay.py`) does one validation from start to finish:

1. **Fetch.** SVS keeps its own bare mirror of the repository under `svs.yara.mirror_dir`
   (`saq/svs/yara/repository.py`). It is never the checkout the yara service loads, so a validation
   cannot change what production scans. The mirror fetches the head commit's branch and the
   repository's configured branch. A commit no fetched branch contains any more (a rebased PR) is
   fetched by id, which most servers allow for a reachable commit. Only one validation fetches a
   given mirror at a time.
2. **Export.** Each commit's tree is unpacked with `git archive` into a private working directory
   under `svs.yara.work_dir`. Unpacking refuses absolute paths, paths that leave the directory,
   links that point outside it and device files, and records each one it refused. The export can
   be capped by `svs.yara.max_archive_bytes` and `max_archive_members` (no limit by default). Like
   any `git archive`, it honours the commit's `.gitattributes` (`export-ignore`), which a checkout does not.
3. **Copy the samples.** Every stored capture is read (`saq/svs/yara/corpus.py`). A **scan unit**
   is a distinct (sha256, file path, `yara_meta` tags): the path sets the `filename`, `filepath` and
   `extension` externals and the `file_ext`/`file_name` filters, and the tags set the `meta_tags`
   filters. Each unit is written to `<work dir>/u/<n>/files/<file path>`, the tail of the path the
   file had in its alert's storage directory, and a rule matches a file if it matches any of its
   units. The labels are read in the same transaction as the captures.
4. **Compile and scan, once per commit,** in the sandbox (below), with no network.
5. **Read the rules from source,** for their uuids and content hashes, the way the signature
   inventory reads them (`saq/signatures/loaders/yara.py`).
6. **Compare** the two scans against the labels (`saq/svs/yara/diff.py`).

The working directory is deleted when the validation ends, whether it succeeded or not.

### Compiling the way the yara service does

`saq/svs/yara/child.py` follows `YaraScanner.compile_and_load_rules` (yara_scanner 3.0.0), which
the yara service runs for each generation, but calls `yara.compile()` itself so the errors and the
compiler warnings are kept:

1. Each rule file is compiled on its own, with the library's include callback. A file that does not
   compile is dropped with its rules, and the report says which rules went with it. An include that
   cannot be read becomes empty text, as in the service, and is reported. So is an include that
   resolves outside the repository, because it reads something else in production.
2. The surviving files are compiled together, one source per namespace. If that fails (two files
   in one namespace defining the same rule name, for instance), **the ruleset would not load**: the
   service keeps serving its previous generation. Nothing is compared, and the report says so. A
   file that is not UTF-8 text fails the whole load the same way, because the service reads it
   before it compiles it.
3. Each namespace is then compiled on its own and every unit is scanned with it, which is what
   gives the scan time per namespace. Namespaces are independent in YARA (a global rule applies
   only to its own namespace), so together these match what the combined rules match. Each scan
   goes through `YaraScanner.scan()`, with the yara service's `default_timeout` per file and
   namespace, so the externals and the meta filters behave as in production.

The scan applies the `enabled` meta and the `qa` and `no_alert` modifiers the way the YARA module
does (`saq/signatures/yara_meta.py`): a **match** means the rule would make a detection. The raw
match is kept too, so a rule that still matches but was switched to QA mode reads as what it is.

### The sandbox

The compile and the scan run in the Landlock sandbox (`saq/sandbox/`), under the limits in
`svs.yara.sandbox`. The process can read only the system libraries and the python runtime, can write
only the working directory, and can open no TCP connection (`allowed_tcp_ports: []`). It cannot
read anything under `SAQ_HOME`, so it imports nothing from ACE; `child.py` is copied into the
working directory and run with `python3 -I`. The whole run is bounded by
`svs.yara.scan_timeout_seconds`. If Landlock is unavailable, a validation fails rather than run
unsandboxed.

### The SVS node is a malware store

The working directory holds a **plaintext** copy of every sample while a validation runs. That is
inherent in scanning (FR-12). Give the node that runs validations AV exclusions for
`svs.yara.work_dir`, disk encryption and restricted shell access. The files are copied out of the
pool, never linked to its read cache, so the sandboxed scan cannot change what the pool serves.

Samples whose bytes are on another node's local pool are not replayed; the report counts them as
`wrong_node`. A multi-node site gives the `svs_samples` pool a shared backend (`docs/SVS_SAMPLES.md`,
*Nodes*).

## The report

Each (sample, rule uuid) pair is decided under base and under head:

| own label | base | head | category |
|---|---|---|---|
| tp | match | miss | `regression` |
| tp (unconfirmed: `inherited_multi`) | match | miss | `regression_unconfirmed`: check that the sample was ever a real hit for the rule |
| tp | miss | match | `recovered` |
| tp | miss | miss | `already_broken` |
| fp | match | miss | `improvement` |
| fp | miss | match | `new_fp` |
| fp | match | match | `known_fp` (counted) |
| none or conflicted | differs | differs | `unlabeled_change` |

A rule that newly matches a file captured for **another** rule is judged by the labels that file
has. If every one is fp, it is `new_fp_other_rule`; if any is tp, `new_match_real_hit`, which is for
information. Anything else is an `unlabeled_change`. A rule's own label always wins over the
file's.

Before any of that:
- A rule in neither commit belongs to another repository and is left out.
- A sample retired for its rule is only counted (`retired`). Retiring is an analyst action on the
  sample (`docs/SVS_SAMPLES.md`, *Actions*); it is how an intended regression stops being reported.
- A rule whose uuid two rules of head share is `not_testable`: their samples cannot tell them apart.
- A sample of a rule head no longer has is `rule_removed`.
- A scan that failed or timed out in the rule's namespace is `scan_error`, never a miss.

Categories marked *counted*, and pairs that did not change (`unchanged`), are counted but not listed.

The report also carries, for each commit:
- the files that do not compile and the rules they drop;
- whether the ruleset would load;
- include problems;
- rule files the yara service would not load (loose in `signature_dir`, or nested below a namespace
  directory);
- archive members that were refused;
- scan time per namespace.

For head it also lists:
- the compiler warnings;
- the rules added, removed and changed (by content hash);
- rules without a uuid;
- rules that filter on `full_path`. The original path held the alert's storage directory, so a
  replay cannot reproduce that filter.

## API

`/api/v2/svs/yara/validations` (`docs/SVS_API.md`, *Validations*):

- `POST /` and `GET /{uuid}/status`, with `svs:validate`: what CI uses. The status carries the
  state, the counts, and the rules (names and uuids) in each listed category, never a sample.
- `GET /`, `GET /{uuid}` and `GET /{uuid}/results`, with `signature:read`: the validations, a
  report, and the pairs it lists with their samples' sha256s; each list also exports as NDJSON and
  CSV.
- `GET /{uuid}/download`, with `signature:download`: the files of a selection of the rows, in an
  `infected` zip, as the Samples download serves them.

## In the GUI

*Signatures → Validations* (`app/signatures/views/validations.py`) lists the validations, for
anyone with `signature:read`. Like *Samples*, it is a shell: everything on it comes from
`/api/v2/svs/yara/validations`, through the list controller `static/js/filter_list_page.js`.

**The list.** One row per validation, newest first, in keyset pages of 25 to 250 rows:
- when it was requested, linking to its report;
- its state (*queued*, *running*, *completed*, *failed*), with a failure's error in the tooltip;
- the repository, and the branch with a link to the pull request when CI sent one;
- the base and head commits;
- who requested it;
- the regressions, new false positives and compile errors, in red when not zero, and a dash until
  it completes.

**Filters, saved filters and links** work as on the Samples page. The filters are repository,
branch, head commit (a prefix), state, has regressions, has new FP, compile errors and created.
Every user starts with the saved filters *Has regressions* and *Failed*. *Export* has CSV and
NDJSON and *Copy API URL*; there is no bulk download from the list.

**A report** (`/ace/signatures/validations/<uuid>`, the link CI posts) shows:
- the header: state, error, repository, branch and pull request, both commits, who requested it,
  when it was requested and ran, and how many rules head adds, removes and changes. A queued or
  running validation's page refreshes every 15 seconds until it ends;
- a red banner when a ruleset would not load, so nothing was compared. For head, that means the
  yara service would keep serving its previous rules;
- the bands, most urgent first: regressions; regressions on unconfirmed labels; new false
  positives, and new false positives on another rule's sample; compile problems (files that do not
  compile and the rules they drop, a ruleset that would not load, includes compiled as empty); scan
  errors; samples of rules the change removes; recovered; improvements; already broken on base;
  new matches on files that are a real hit for another rule; and unlabeled changes. Each band has
  its count and a line on what to do with it. The urgent ones are open, the others are opened with
  a click, and an empty band is left out;
- under the bands, the counted categories: known false positives still matching, retired, not
  testable and unchanged;
- *Details*: the rules the change adds, removes and changes, rules that cannot be tested and
  why, rules that filter on `full_path`, head's compiler warnings, rule files the yara service would
  not load, refused archive members, samples that were not scanned, the scan time per namespace
  under base and head, and the run (sizes, duration, library versions, worker, corpus version and
  engine fingerprint).

A band lists 50 rows at a time, with *Show more*. Each row has the rule and its namespace, the
file's sha256, the sample's label for the rule (drawn like a detection verdict), the outcome under
base and under head, and a note (for example, why a match makes no detection). An icon marks a
rule that matched where its meta makes no detection. The rule links to the sample's page, where
the actions are (`docs/SVS_SAMPLES.md`, *Actions*: retire an intended regression, relabel a wrong
label). In the bands whose file is not a sample of that rule (new false positives on another
rule's sample, new matches on a real-hit file, unlabeled changes, scan errors), it links to the
Samples list filtered on the file's sha256 instead.

Each band exports its rows as CSV or NDJSON, and so does the whole report. With
`signature:download`, each band and the whole report also have *Download files*: the files of
those rows that are stored on this node, in a zip with the password `infected`.

## Command line

```bash
ace svs yara layout
ace svs yara validate --repository signatures --base <merge base> --head <head commit> [--branch <head branch>] [--json]
ace svs yara prune [--dry-run] [--force]
```

`validate` runs a validation synchronously, without the queue, and prints the report, or the whole
result as JSON with `--json`; it stores nothing. It counts the samples retired at the time it runs
as `retired`. It exits 1 when the validation could not run (an unknown repository or commit, no
Landlock, a failed export or scan). `prune` removes the finished validations older than
`svs.yara.retention_days`; it does nothing off the primary node unless given `--force`.

## Configuration

```yaml
svs:
  yara:
    repositories: []              # git_repo_<name> sections whose commits may be validated
    scan_timeout_seconds: 1800    # compiling and scanning one commit's rules over the corpus
    max_concurrent_validations: 1 # service_svs workers
    retention_days: 90            # how long a finished validation and its report are kept
    prune_batch_size: 100         # validations one prune transaction removes
    fetch_timeout_seconds: 600    # fetching into the mirror; the first fetch clones it
    # max_archive_bytes: 536870912  # optional cap on the export of one commit; unset means no limit
    # max_archive_members: 100000   # optional cap on its files and directories; unset means no limit
    mirror_dir: svs/mirrors       # relative to DATA_DIR
    work_dir: svs/work            # relative to DATA_DIR; must allow execution and have no '.' in its path
    sandbox:
      memory_limit: 4294967296
      allowed_tcp_ports: []

service_svs:
  enabled: true                   # idle while svs.yara.repositories is empty, and off the primary node
  shutdown_deadline_seconds: 30   # a stopping worker cancels its scan and requeues its validation
  poll_interval_seconds: 5
  heartbeat_interval_seconds: 30  # at most a third of lease_seconds
  lease_seconds: 300
  max_attempts: 3
```

`work_dir` must not have a `.` in its path. The `extension` external and the `file_ext` filter take
everything after the last `.` of the whole path, so a `.` above the sample would change them for a
file name without one. On a kernel older than Linux 6.7, Landlock cannot restrict TCP and every
sandboxed command fails unless `sandbox.allowed_tcp_ports` is `null`.
