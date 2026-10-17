# SVS coverage

SVS coverage answers "which ATT&CK techniques do we actually detect?" from the Atomic Red Team test
runs that analysts review (`docs/SVS_RUNS.md`), together with the technique tags signatures already
carry (`docs/SVS.md`, Part 4).

This document covers how coverage works in ACE and how to operate it. It grows with phase 5. Today
it covers how coverage is computed, refreshed and snapshotted, and the ATT&CK release it is computed
against. The design and its reasoning are in `docs/SVS.md`. Coverage is read through
`/api/v2/svs/coverage` (`svs:run_read`), whose data dictionary is `docs/SVS_API.md`, *Coverage* and
*Coverage history*.

## Rows

Coverage is one row per **(technique, platform)**, in the `svs_coverage` table. Coverage is global,
not per company.

A technique has rows on:
- every platform ATT&CK lists for it;
- every platform of its tests;
- for a parent technique, every platform of its sub-techniques' rows.

`attack_platform` says whether ATT&CK itself lists the platform for the technique. A test can run
somewhere ATT&CK doesn't list; for example, some IaaS atomics run from linux.

Which techniques have rows:
- every active technique of the pinned release;
- a deprecated or unknown technique, only while a test or a counting tag names it;
- the parent of each of those.

A row is never deleted. When nothing produces it any more (a test was removed from its repository,
an ATT&CK upgrade revoked the technique), it gets `retired_at`. It comes back, with `retired_at`
cleared, if something produces it again.

## Platforms

A test counts on each of its supported platforms. It also counts on any platform it has a run or
an expectation on (`docs/SVS_RUNS.md`). A run's platform is the platform of its targets, and
expectations are kept per platform, so each platform of a multi-platform test is judged on its own.

## States

A test contributes one state to the row of its technique on each of its platforms. That state is
the test's state on that platform, which is the same judgment the Tests tab shows: the latest
reviewed run there, against what is expected of the test there, minus ignores
(`saq/svs/test_state.py`).

| The test on the platform | Counts as |
|---|---|
| *validated* | **validated** |
| *failing* | **failing** |
| *stale* | **stale** |
| Something is expected that its latest reviewed run there didn't judge (the Tests tab shows *awaiting review*) | **stale** |
| Never run there, no reviewed run there, or nothing expected there | **untested** |

A signature's tag adds **manual** (below). A row's state is the worst of everything counting
toward it:

**failing** > **stale** > **validated** > **manual** > **untested** > **none**

A row nothing counts toward is **none**. *Failing* means that a test of the technique missed an
expected signature. It doesn't mean that the technique goes undetected.

A row also carries counts over the same tests and signatures as its state:
- `tests_total`, `tests_validated`, `tests_failing`, `tests_stale`;
- `manual_signatures`, the signatures whose tags count toward it;
- `measured_signatures`, the signatures expected of its tests on the platform;
- `last_reviewed_at`.

Catalog tests removed from their repository don't count.

## Roll-up

A parent technique's row counts its sub-techniques' rows on the same platform, so T1059 on
windows is *failing* when a T1059.001 test failed there. `state` is rolled up. `own_state` covers
only what names the technique itself, and `parent` and `is_subtechnique` say where a row sits.

## Manual mappings

A signature's `mitre:` tags claim techniques without a test: a hunt's `tags`, and a YARA rule's tags,
which include its `mitre_attack` meta.
- A tag counts only when the signature is enabled, and, for a YARA rule, not in QA mode
  (`docs/YARA_QA.md`).
- A tag on technique t makes every row of t **manual**. It doesn't reach t's sub-techniques, but it
  rolls up to t's parent like anything else.
- Tags are matched case-insensitively against `T1234` or `T1234.567`. A revoked id counts as its
  successor.
- A tag naming an id the release doesn't have doesn't count. Neither does a tag that isn't a
  technique id at all, such as a tactic (`mitre:TA0002`) or a template (`mitre:{{ technique }}`).
  Both are counted (`unknown_tags`, `ignored_tags`) in `ace svs coverage status`.

## Refresh

`service_svs` recomputes coverage every `svs.coverage.refresh_interval_seconds` (default 120), on the
primary node only (`saq/svs/coverage.py`). Coverage therefore trails a review or a new expectation
by at most that interval.

A refresh:
1. reads the signatures' tags from the hunts and the YARA rule inventory;
2. locks the single row of `svs_coverage_state`, so two refreshes never interleave;
3. reads the catalog tests, their runs, expectations and ignores, and computes every row;
4. writes only the columns that changed, so a row's `updated_at` moves only on a real change. It
   inserts new rows and retires missing ones;
5. records what it did on `svs_coverage_state`, and commits once.

If anything fails, nothing is written. For example, a YARA rule location might not be readable; a
partial inventory would make every YARA manual mapping vanish for one refresh. The error is
recorded on `svs_coverage_state` and logged, and the next refresh tries again.

```
ace svs coverage refresh [--force]   # refresh now; --force off the primary node
ace svs coverage status              # the last refresh, its error, and rows per state on each platform
```

Each refresh logs *svs coverage refreshed* with `attack_release`, `rows`, `changed`, `retired`,
`duration_ms` and `actor`. Each row whose state changed logs *svs coverage of T… on …* with
`technique`, `platform`, `from_state` and `to_state` (`docs/SVS.md`, *Logging contract*).

## Snapshots

Coverage is the current state only; a report of coverage over time needs history, which can't be
rebuilt later (`docs/SVS.md`, Part 6, *History kept for reports*). So once a day the primary node
files a copy of it in `svs_coverage_snapshots`:

```
ace svs coverage snapshot [--force]   # refresh, then file today's (UTC) snapshot; --force off the primary node
```

`etc/cron/daily/svs-coverage-snapshot` runs it (`docs/CRON.md`). The command:
1. refreshes coverage, exactly as `ace svs coverage refresh` does. If the refresh fails, no
   snapshot is written and the command exits 1, so the cron job reports it;
2. locks `svs_coverage_state`, like a refresh, and copies every row that isn't retired under
   today's UTC date: its state, own state, test counts, manual and measured signature counts, and
   the ATT&CK release.

A second snapshot on the same day replaces the day: its rows are rewritten (a row that didn't change
keeps its `updated_at`), and the day's rows that are no longer in coverage are removed. A day the
job didn't run has no snapshot; there is no way to file one afterwards, because it would be today's
coverage under another date. Snapshots are kept forever: about 1,900 rows a day with the vendored
release and the Atomic Red Team catalog.

Each snapshot logs *svs coverage snapshot of … written* with `snapshot_date`, `rows`,
`attack_release` and `actor`.

`GET /api/v2/svs/coverage/history` lists the snapshot rows, and `…/history/counts?group=day|month`
counts them per state: per day, or per month from each month's last snapshot.

## The ATT&CK release

Coverage needs ATT&CK itself for technique and tactic names, to roll sub-techniques up to their
parents, for each technique's platforms, and to know where a revoked technique went. Atomic Red
Team supplies only the technique id of each test.

**Production ACE never fetches ATT&CK.** Each supported release is vendored in this repository as a
compact extract, `etc/attack/<release>.json`. `etc/` is copied into the image. The setting
`svs.attack_release` (default `v20.0`) names the extract in use. Startup fails config validation
when that file is missing:

```
svs.attack_release v21.0: /opt/ace/etc/attack/v21.0.json is missing; bin/update-attack-catalog v21.0 builds it
```

### What the extract holds

The extract is built from MITRE's enterprise STIX bundle for the release. It holds only what SVS
uses:

| Key | Contents |
|---|---|
| `release`, `domain`, `source` | The release (`v20.0`), `enterprise-attack`, and the URL and sha256 of the bundle it was built from |
| `platforms` | The platform slugs coverage uses, in display order, with ATT&CK's name for each |
| `tactics` | Every tactic in the matrix's order: id (`TA0002`), shortname (`execution`), name |
| `techniques` | Per technique id (`T1059`, `T1059.001`): name, parent (sub-techniques only), tactic ids, platform slugs, and `deprecated` |
| `revoked` | Revoked id → the current technique that replaces it |
| `renamed` | Informational: techniques whose name changed since a previous extract |

**Platforms** get stable slugs: `windows`, `linux`, `macos`, `esxi`, `iaas`, `containers`, `saas`,
`office-suite`, `identity-provider`, `network-devices`, `pre`. Older ATT&CK names map onto them
("Office 365" and "Google Workspace" → `office-suite`, "Azure AD" → `identity-provider`,
"Network" → `network-devices`). A test's `supported_platforms` uses Atomic Red Team's names, which
map the same way: `iaas:aws`, `iaas:azure` and `iaas:gcp` → `iaas`, `azure-ad` →
`identity-provider`, `office-365` and `google-workspace` → `office-suite`.

**Revoked, deprecated and renamed** mean different things:
- **Revoked.** ATT&CK replaced the technique with another one, often when it became a
  sub-technique (T1086 PowerShell → T1059.001). Wherever SVS reads a technique id, from an atomic
  or a signature's tag, a revoked id counts as its successor. Revocations of revocations are
  followed to the end (T1150 → T1547.011 → T1647).
- **Deprecated.** ATT&CK retired the technique without a replacement. It keeps its id, name and
  platforms in the extract, marked `deprecated`, so a test or tag that still names it isn't lost.
- **Renamed.** A rename keeps the technique's id, and ids are the key everywhere in SVS, so a
  rename needs no remapping: names always come from the pinned release. One STIX bundle can't show
  that a rename happened, so `renamed` is filled only when the extract is built with `--previous`,
  for the upgrade notes.

An id that isn't in the release at all, such as a custom atomic's technique or a typo, is kept as it
is and shown as *unknown*.

### Adding or upgrading a release

`bin/update-attack-catalog` builds an extract. It is a developer tool and needs network access to
GitHub. It downloads `enterprise-attack/enterprise-attack-<version>.json` from MITRE's
[attack-stix-data](https://github.com/mitre-attack/attack-stix-data) repository:

```bash
bin/update-attack-catalog v21.0 --previous etc/attack/v20.0.json
```

- `--input FILE` builds from a bundle already on disk instead of downloading it.
- `--output-dir DIR` writes somewhere other than `etc/attack/`.
- The output is deterministic, so rebuilding a release writes the same bytes, and a new release
  reviews as a readable diff against the previous one.
- The build stops on anything it can't place, rather than dropping it:
  - a platform name it has no slug for (add it to `PLATFORMS` or `PLATFORM_NAMES` in the script);
  - a tactic the bundle doesn't define;
  - a cycle of revocations;
  - a bundle that says it is a different release.
- A revoked technique whose successor is missing from the bundle is left out of `revoked`, with a
  warning.

To move a site to the new release, commit the extract and change `attack_release`. Keep the
previous extract in the repository until no site uses it.
