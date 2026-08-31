# Observable Detections

An *observable detection* is an observable value that ACE should alert on whenever it sees it: an
analyst-curated indicator. Analysts create them from the alert view ("enable detection" on an
observable), from the admin detection page, or in bulk through the API. Each is a row in the
`observable_detections` table (`saq/database/model.py::ObservableDetection`) carrying the observable
type and value, an optional expiration, and free-text context explaining why it was enabled. A
detection does not need the value to have ever been seen -- adding one ahead of the first sighting is
the point.

All reads and writes go through `saq/database/util/observable_detection.py`, which normalizes the value
through the real observable class so that what is stored is exactly what the analysis engine will
produce at runtime.

## How ACE itself matches

`saq/modules/observable_detection.py::ObservableDetectionAnalyzer` runs against every observable of
every alert and looks the observable up in a node-local redis cache under the key `{type}:{value}`. On a
hit it adds a detection point and the tag `detect_{type}`.

Two properties of that match matter to anything built on top of it:

- It is **exact and case-sensitive**. Only observable types that normalize their value (email
  addresses are lowercased) match regardless of case; an fqdn, url, or user agent matches only in the
  case the detection was created with.
- It matches on the **exact type**. A detection on `email_reply_to` does not fire on an `email_from`
  observable with the same value (see the note in `OBSERVABLE_TYPE_INHERITANCE.md`).

## Exports

The redis cache is only one of several places the detections are published to. `ace observables
export` (run by cron every minute, see `etc/cron.yaml`) materializes the active detections into every
enabled export target, and is a no-op for a target when nothing changed since it last published. Targets
are configured as `observable_export_<name>:` blocks and implemented as `ObservableExport` subclasses
under `saq/observables/export/`:

| target | config block | what it produces |
|---|---|---|
| redis | `observable_export_redis` | the cache the analysis engine matches against |
| yara | `observable_export_yara` | one yara rule file per observable type, scanned against files |
| splunk | `observable_export_splunk` (`etc/saq.splunk.default.yaml`) | a KV store collection that Splunk hunts search |

The yara target publishes each detection under the parent type its `export_list` names
(`email_reply_to` becomes `email_address`), because a yara rule scanning a blob of data has no way to
know the context ACE knew. The splunk target exports **every** active detection under its **exact**
type: which types are worth hunting is a hunt-side decision, an exported type no hunt selects costs
nothing, and keeping the exact type is what lets the engine's own exact-type match fire on the
alerts a hunt creates. It follows that enabling a detection on a newly added observable type needs
no ACE config change -- the type reaches the collection on the next export, and only the hunt
consuming it has to exist.

## The Splunk KV store collection

Disabled by default: a stock install has no Splunk to publish to. Enable it by setting `collection` and
`enabled: true` in a site overlay. The exporter writes one document per active detection, of every
type:

| field | value |
|---|---|
| `_key` | the `observable_detections` row id, as a string; publishing is an upsert on it |
| `id` | the same id, as a number |
| `type` | the exact observable type the detection was created with |
| `type_path` | `type` plus its ancestors from the type hierarchy, space-joined, most specific first (`email_reply_to email_address`) -- what a hunt selects a type family by, after `makemv` |
| `value` | the detection exactly as ACE stores it -- what a hunt searches for, and what it reports back as the observable so the engine's own match fires on the resulting alert |
| `pattern` | `value` lowercased and wrapped in `*`; for `url` and `uri_path` the scheme and any trailing `/` are removed first so the pattern is a substring of however a log renders the url |

`type_path` is derived from the observable type registry (`observable_types.config_path`) at publish
time and is not part of the change-detection fingerprint, so an edit to the hierarchy alone reaches
the collection on the next publish -- the next detection change, or an
`ace observables export --force splunk` -- not the next export run. A type absent from the registry
(legacy detections can carry one) exports with a self-only `type_path`.

A literal `*` in a value is left as a wildcard in `pattern`. A url detection with no path
(`http://evil.com/`) therefore becomes `*evil.com*` and matches every url on that host; an analyst who
means the host should enable an `fqdn` detection instead.

### One-time Splunk setup

The exporter does not create Splunk objects. In the app the export connects through (the `app_context`
of the `splunk_config_<api>` block), shared globally, create:

1. A KV store collection named as configured in `collection`, with fields `id` (number), `type`,
   `type_path`, `value`, `pattern` (string), and an accelerated field over `type` + `value`.
2. A lookup definition `ace_detections` over that collection with
   `fields_list = _key, id, type, type_path, value, pattern`, used with `inputlookup`.
3. A lookup definition `ace_detections_pattern` over the same collection with the same fields plus
   `match_type = WILDCARD(pattern)` and a `max_matches` large enough for an event that contains several
   indicators, used with `lookup`. A field missing from a `fields_list` is silently absent from that
   lookup's output, so both definitions must list all five.

Until the collection exists the export logs an error every minute; once it exists the next run
publishes. On a search head cluster a KV store write takes a few seconds to reach every member, so a
search run immediately after a publish can miss a new row; at the export's one-minute cadence that
never matters, but it will surprise a hand test that seeds a row and searches straight away. The exporter only publishes when the set of detections changed, so an environment that has
already published in an older document shape needs one `ace observables export --force splunk` to
rewrite it.

### How a hunt uses it

A hunt per observable type (or type family) selects its detections by `type_path`, turns them into
search terms, then uses the pattern lookup to learn which detection each event contains:

```
index=* NOT index=<ace's own log index>
  [| inputlookup ace_detections
   | makemv type_path
   | search type_path="fqdn"
   | eval myCandidate=value
   | eval myTerm=if(match(myCandidate, "[\\s\"'()\\[\\]{}<>|!;,*&?+]"),
                    "\"" . replace(myCandidate, "([\"\\\\])", "\\\\\\1") . "\"",
                    "TERM(" . myCandidate . ")")
   | stats values(myTerm) AS myTerms
   | where mvcount(myTerms) > 0
   | eval search="(" . mvjoin(myTerms, " OR ") . ")"
   | fields search]
| eval myRawLc=lower(_raw)
| lookup ace_detections_pattern pattern AS myRawLc
    OUTPUT id AS myDetectionId value AS myDetectionValue type AS myDetectionType type_path AS myDetectionTypePath
| where isnotnull(myDetectionId)
```

`search type_path="fqdn"` after `makemv` matches an exact element of the path, never a substring --
`type_path="ip"` selects `ip` and its subtypes, not `uri_path`. Selecting a family
(`type_path="email_address"`) picks up every subtype's detections in one hunt while each stays
exported under its exact type. The pattern lookup joins on `pattern` alone, so it attributes every
detection the event contains, including one from another family that the hunt's search terms
happened to surface; a hunt that should stay within its family filters the expanded results on
`myDetectionTypePath`. The observable the hunt reports is `myDetectionValue` under
`myDetectionType` -- the exact type and original case the detection was created with, which is what
the engine's own exact-type, case-sensitive match recognizes.

The subsearch returns a single field named `search`, which Splunk inserts into the outer search
verbatim (only when `format` is *not* applied -- `format` would quote it into a phrase). No rows means
no search at all. Each value becomes:

- `TERM(value)` when the value contains no whitespace or other major breaker. That is an index-only
  lookup and is what keeps an `index=*` search affordable: measured over a 5-minute window across every
  index, ~50 seconds for a value that appears nowhere versus ~285 seconds for the same value as a
  quoted phrase, which has to raw-scan every event whose minor tokens (`com`, `1`, `2`, ...) match.
  The cost grows with the number of terms, though: 500 absent `TERM()`s over a 2-minute window across
  every index did not finish in 5 minutes. `index=*` is affordable while a type has tens of detections;
  a type with hundreds needs the hunt narrowed to the indexes where it appears.
  `TERM()` matches a value that stands on its own in the raw event (quoted in JSON, a CSV column,
  space-delimited). In a feed that logs tab- or space-separated `key=value` pairs, `=` is a *minor*
  breaker, so a value containing `.`, `@`, `/` or `-` is indexed only as the whole `key=value` token
  and the bare `TERM(value)` misses it (measured: 0 hits for a domain and an IP that were present in
  every event). Each hunt therefore also emits `TERM(key=value)` for the field names its type is known
  to be logged under, and `TERM(key=value/*)`-style trailing-wildcard forms where the value starts a
  longer token; both stay index-only. A leading wildcard (`TERM(*=value)`) is a lexicon scan and is
  never used. A value buried anywhere else inside a longer token is not found, and needs a
  field-level match once the hunt is narrowed.
- a quoted phrase otherwise (user agents, subjects, file names with spaces). Correct, but each such
  detection costs the raw scan above on every run.

A url hunt also searches the scheme-stripped form and the `http://` / `https://` variants, since logs
disagree on which they store. The lookup then runs only on the events that survived, matching each
detection's `pattern` against the lowercased raw event. Exclude ACE's own log index from the search:
it echoes the detection values back. Matching the whole raw event is deliberately broad; a hunt is
narrowed to specific indexes and fields once it is known where a type actually appears.

A detection of a type no hunt selects sits inert in the collection. That is by design -- an untested
type must not be injected into an `index=*` search just because someone enabled it, and a type may be
deliberately hunted in a different backend or matched only in-engine and by the yara export -- but it
means the gap is silent: nothing distinguishes "hunted elsewhere" from "nobody wrote the hunt". When
enabling a detection on a type for the first time, check that a hunt actually selects its
`type_path` wherever it is expected to be hunted.
