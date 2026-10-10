# SVS YARA validation

A change to YARA rules is checked against the samples analysts have graded (`docs/SVS_SAMPLES.md`):
every stored sample is scanned with the rules as they are on the base commit and as they are on the
head commit, and the two scans are compared against the labels. A file graded as a real hit that
stops matching is a **regression**; a file graded as a false positive that starts matching is a
**new false positive**. The report warns and never blocks.

This document covers how a validation runs and what it reports. The design and its reasoning are in
`docs/SVS.md`, Part 2, *Validation* and *Report and baseline*.

Today a validation runs from the command line (`ace svs yara validate`), synchronously, and stores
nothing. The validation queue, its API and the CI client come next.

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
- A sample retired for its rule is only counted (`retired`).
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

## Command line

```bash
ace svs yara layout
ace svs yara validate --repository signatures --base <merge base> --head <head commit> [--branch <head branch>] [--json]
```

`validate` prints the report, or the whole result as JSON with `--json`. It exits 1 when the
validation could not run (an unknown repository or commit, no Landlock, a failed export or scan).

## Configuration

```yaml
svs:
  yara:
    repositories: []              # git_repo_<name> sections whose commits may be validated
    scan_timeout_seconds: 1800    # compiling and scanning one commit's rules over the corpus
    max_concurrent_validations: 1
    fetch_timeout_seconds: 600    # fetching into the mirror; the first fetch clones it
    # max_archive_bytes: 536870912  # optional cap on the export of one commit; unset means no limit
    # max_archive_members: 100000   # optional cap on its files and directories; unset means no limit
    mirror_dir: svs/mirrors       # relative to DATA_DIR
    work_dir: svs/work            # relative to DATA_DIR; must allow execution and have no '.' in its path
    sandbox:
      memory_limit: 4294967296
      allowed_tcp_ports: []
```

`work_dir` must not have a `.` in its path. The `extension` external and the `file_ext` filter take
everything after the last `.` of the whole path, so a `.` above the sample would change them for a
file name without one. On a kernel older than Linux 6.7, Landlock cannot restrict TCP and every
sandboxed command fails unless `sandbox.allowed_tcp_ports` is `null`.
