# Alert filter URLs

A link to the alert management page can carry a filter with it:

```
https://ace.example.com/ace/manage?f=queue:default&f=alert_date:-7d&f=!tag:whitelisted
```

The link contains the filter itself rather than an id, so it keeps working forever — after
the filter it was copied from is renamed, edited, or deleted, and after the analyst who
made it leaves. That is what makes it safe to paste into a wiki page or a ticket.

Opening one applies it as a **temporary** filter: whatever filter you were already using is
untouched and one click away under *Revert*.

## Format

```
f = [!] <slug> : <value> [, <value> ...]
```

- One `f` parameter per filter. Separate parameters are **ANDed**; commas within one are
  **ORed**. Repeats of the same filter with the same polarity are merged into one before the
  query runs, so `f=queue:a&f=queue:b` means either queue, exactly like `f=queue:a,b`.
- A leading `!` inverts the filter (`!tag:whitelisted` = alerts *without* that tag).
- Filters are named by a stable **slug**, not by the label shown in the GUI.

| slug | filter | | slug | filter |
|---|---|---|---|---|
| `alert_date` | Alert Date | | `event_date` | Event Date |
| `alert_type` | Alert Type | | `observable` | Observable |
| `analysis` | Analysis | | `owner` | Owner |
| `description` | Description | | `queue` | Queue |
| `disposition` | Disposition | | `reviewed` | Reviewed |
| `disposition_by` | Disposition By | | `tag` | Tag |
| `disposition_date` | Disposition Date | | `detection_point` | Detection Point |
| `unconfirmed_detections` | Unconfirmed Detections | | `observable_pattern` | Observable Pattern |
| `remediation` | Remediation | | | |

`unconfirmed_detections:True` finds alerts with a detection whose verdict nobody has confirmed: an
inherited TP on a TP alert where several signatures fired (`docs/SVS.md`, Part 1); `False` the rest.

`remediation` finds alerts by the state of their email remediation, the one the manage page's
Remediation column shows (`saq/remediation/coverage.py`). Like `observable`, its value is a pair,
`<source>:<state>`, with the colon between them literal:

```
f=remediation:Any:failed
f=remediation:defender_email_probe:watching
```

The source is `Any` for every remediator and probe, which is what the column counts, or the name
of one: an email remediator (`remediator_*`, matched on `remediation.name`) or an email probe
(`external_remediation_probe_*`, matched on `external_remediation_check.probe_name`). The state is
then read from that source's rows alone, so an alert whose removal by ACE failed and a probe then
confirmed is `remediated` for `Any`, `failed` for the remediator and `remediated` for the probe.
The editor lists `Any` and the sources configured now; a source that is no longer configured still
matches its old rows. The state is one of:

| state | the column shows |
|---|---|
| `remediated` | remediated, every email removed or not in the mailbox |
| `partial` | remediated, some emails still outstanding |
| `failed` | remediation failed: a removal failed and nothing else removed that email |
| `remediating` | remediating: ACE is still removing an email |
| `watching` | watching: a probe is still polling for a vendor's removal |
| `not_remediated` | not remediated: every attempt finished without confirming a removal |
| `not_in_mailbox` | not in mailbox: ACE found nothing to remove, and nothing was removed |
| `none` | nothing: the alert has no email, or the source made no attempt on it |

Inverted, it is the exact complement, so `!remediation:Any:remediated` includes the alerts with no
email at all. The alerts whose remediation started and fell short or is still going are
`remediation:Any:failed,Any:partial,Any:not_remediated,Any:watching,Any:remediating`. Two states
it leaves out can still have copies in mailboxes: `not_in_mailbox`, because the state does not
tell "every copy gone" from "one copy gone, the rest still outstanding", and `none`, where
nothing has been tried.

**What it costs.** The state is computed when the query runs, not stored. An alert with no
remediation activity costs about a microsecond; one with activity costs a read of its observables
and its probe rows, which grows with how many it has (5 ms for one alert with 800 recipients a
probe watched, on a development stack). Within the manage page's usual filters it adds little
(130 ms at 100,000 alerts with the default open-alerts filter, 37 ms for a page of 50), but on its
own it reads every alert with activity: 0.7 s at 100,000 alerts of which 7% have some. A quick
filter badge recounts every 30 seconds, so give a badge that uses it a date range too
(`alert_date:-7d`).

### Escaping

Three characters are structural and must be percent-encoded when they appear **inside a
value**:

| character | encode as |
|---|---|
| `:` | `%3A` |
| `,` | `%2C` |
| `%` | `%25` |

### Observables

Observable values are a type and a value, and the colon between them stays literal:

```
f=observable:ipv4:1.2.3.4
f=observable:url:https%3A%2F%2Fevil.com%2Fa%2Cb
```

The second example is why the value's own colons must be encoded — otherwise
`url:https://evil.com` would parse as an observable of type `https`.

### Observable patterns

`observable_pattern` takes the same type and value pair, with the type `Any` for any type, and
the value is a pattern in which `*` matches anything:

```
f=observable_pattern:fqdn:%2A.evil.com
f=observable_pattern:url:https%3A%2F%2Fevil.com%2Flogin%2A
```

A `*` in the `observable` filter is a literal character, so a value that contains one, such as
an email subject like `***SPAM***`, is still matched exactly there, and so is every observable
clicked from an alert.

The pattern has to start or end with text. `observable_pattern:fqdn:*.evil.com`,
`observable_pattern:url:https://evil.com/*` and `observable_pattern:fqdn:evil.com*.net` are
accepted. `*evil*` is refused when the filter is saved, applied or sent to the API, because a
pattern with a wildcard at both ends can only be answered by reading every row of `observables`
(over a second at 1.25 million rows), and the filter runs on every page load, every 30 second
refresh and every badge count.

How it is matched (`ObservablePatternFilter`, `saq/gui/filter_query.py`):

- **Against the stored bytes, case included.** The pattern goes through the type's own class
  only when the class changes nothing but its case: `email_address` stores addresses lowercased,
  so `*@Evil.com` matches `bob@evil.com`. An `fqdn` keeps the case it was found in, so
  `*.evil.com` does not match `Mail.EVIL.com`, as the exact filter does not.
- **`%`, `_` and `\` are literal.** Only `*` is a wildcard.
- **Through an index.** A pattern that starts with text is a range scan of `i_obs_value`. One
  that starts with `*` is a range scan of `i_obs_value_rev`, the index on `observables.value_rev`,
  which is the last 255 bytes of the value reversed; the whole value is still checked, so a longer
  suffix is matched correctly.
- **In two steps.** The matching observables' ids are looked up first, and the alerts are then
  found through `observable_mapping`'s primary key, which the query names with `FORCE INDEX`:
  for the inverted form MySQL otherwise scans the whole table. The lookup is refused, and the alert list shows the reason
  instead of any alerts, when the patterns of one filter match more than 500 observables between
  them (`MAX_PATTERN_OBSERVABLES`) or take longer than one second (`PATTERN_LOOKUP_TIMEOUT_MS`,
  enforced by MySQL's `MAX_EXECUTION_TIME`). A partial list of ids would quietly leave alerts
  out. The API answers 422 with the same reason, the search box returns it as an error, and a
  quick filter badge whose pattern cannot be run shows a warning mark whose tooltip is the
  reason, rather than looking like a filter with no alerts.
- **A refusal is remembered.** A pattern refused for either limit is refused again without a
  lookup for five minutes (`PATTERN_REFUSAL_TTL_SECONDS`), in that process, because a pinned
  badge and an open manage page run it on every refresh. A pattern that was looked up is not
  remembered: a new observable can match it at any time.

### Analysis

An `analysis` value is an analysis type's module path, `module:Class`, with `:instance` appended
for a module configured more than once. Its colons are part of the value, so they are encoded:

```
f=analysis:saq.modules.file_analysis.qrcode%3AQRCodeAnalysis
```

It matches alerts whose analysis tree *shows* that analysis -- one with a summary or with
observables of its own -- so an analysis that ran and found nothing does not count. The types
come from the `analysis_mapping` index, which the engine keeps with the rest of an alert's
index; alerts analyzed before it existed need `ace alert rebuild --all` (optionally narrowed
with `--insert-date -90d`) to be found by it.

### Dates

Date filters accept either an absolute range or a Splunk-style relative one. **Relative
values are re-evaluated every time the link is opened**, so `alert_date:-7d` still means
"the last week" years after it was written.

```
f=alert_date:-24h                             the last 24 hours
f=alert_date:-7d - now                        the last week, written out
f=alert_date:-1d@d - @d                       all of yesterday, local time
f=alert_date:01-15-2026 08:00 - 01-22-2026 08:00
```

The grammar is `now`, or `[+-]<n><unit>` with an optional `@<unit>` snap, or a bare
`@<unit>`. Units are `s` `m` `h` `d` `w` `y` (and `mon` for a snap). A snap floors to the
start of that unit **in your timezone**, so `@d` is local midnight. `@w` floors to the
preceding Sunday.

### Sentinels

Two values are resolved against whoever opens the link, which is what makes a runbook link
work for a whole team:

| sentinel | becomes |
|---|---|
| `$USER_QUEUE` | the viewer's own queue |
| `$USER` | the viewer's own display name |

```
f=queue:$USER_QUEUE&f=reviewed:UNREVIEWED
```

## The same filters in the API

`GET /api/v2/alerts` (permission `alert:read`) lists alerts as flat database rows, each with
the comments on the alert, for export and reporting (the manage page's Export to CSV button
downloads its CSV export), and takes these filters as repeated `f` query parameters, exactly as written in
a link: copy the part of a manage-page URL after `?` and the API returns the same alerts. Two
differences, both on purpose:

- An unknown slug is a **422**, not a skipped filter with a warning: an API caller has no
  banner to read the warning on, and a silently missing filter returns more alerts than asked
  for.
- Relative dates resolve in the `tz` parameter (default `UTC`) rather than the viewer's GUI
  timezone. `$USER` and `$USER_QUEUE` resolve against the API key's user.

The listing is scoped to the alerts this node shows, like the manage page, and does not leave
test alerts out. Pages are keyset pages: follow `next_cursor` until it is `null`, and no alert
is skipped or repeated while new ones arrive. Rows come in `id` order.

`GET /api/v2/alerts/count` takes the same `f` and `tz` and returns `{"count": N}`, the number of
alerts the listing returns. `GET /api/v2/alerts/date-range?value=-7d&tz=America/Chicago` returns
the window a date value means right now: `start` and `end`, and the `text` the manage page shows
under the relative date input. A value that does not parse is a 422.

`changed_since=<ISO time>` returns only the alerts whose row changed at or after that time,
ordered by `(updated_at, id)`. `alerts.updated_at` is maintained by the database on every
update of the row (a disposition, an owner, a comment, an analysis sync all rotate the row). A
change is returned once it is a few seconds old, so that no transaction still in flight can
commit an older timestamp behind a cursor already handed out. Delivery is at least once: a
client that resumes from the last `updated_at` it saw may see a row again, never miss one.
Alerts that existed before `updated_at` was added carry the time of that migration.

`GET /api/v2/alerts/export/ndjson` and `GET /api/v2/alerts/export/csv` stream the whole result in
one response, with the same parameters and order and no paging: one `AlertRow` per line, or a
header line and one row per alert.

`GET /api/v2/detection-points` lists detections with their verdicts in the same encoding, with the
slugs of its own screen (`signature`, `verdict`, `source`, …), and `GET /api/v2/svs/samples` lists
the SVS YARA samples with theirs (`label`, `sha256`, `missing_data`, …); see `docs/SVS_API.md`.
`GET /api/v2/remediation/remediations` and `GET /api/v2/file-collections/` list remediations and file
collection requests with theirs (`status`, `result`, `created`, …), newest first.

## The same slugs in the search box

The manage-page search box understands these slugs too, so `queue:default` means the same
thing typed as it does in a link (`docs/SEARCH.md`, section 2). It is a sibling grammar, not
the same one, and it differs in four ways on purpose:

- **Values are literal.** A link is generated, so it percent-encodes `:`, `,` and `%`; a search
  box is typed, so it must not demand that. Quote instead: `url:"https://evil.com/a,b"`.
- **`-` also inverts**, alongside `!`, because `!` is awkward in a shell.
- **Any observable type is a prefix of its own**: `ipv4:1.2.3.4` is shorthand for
  `observable:ipv4:1.2.3.4`, and `uuid:` means the *alert* uuid rather than the observable
  type of that name. A pattern has no shorthand: it is `observable_pattern:fqdn:*.evil.com`,
  with the type `any` for any type.
- **`remediation:failed` is every source**, shorthand for `remediation:Any:failed`.

## Links that outlive a filter type

If a link names a filter that no longer exists, the rest of the link is applied and a
warning names what was dropped. It is deliberately not a hard failure — an old link stays
useful — and deliberately not silent, because a missing filter shows *more* alerts than the
link's author intended.

A link that is malformed (a missing colon, an empty value, a bad `%` escape) is an error
rather than a partial match, since guessing would show the wrong alerts.

## Older links

Links in the pre-3.1 format still work:

```
/ace/set_filters?redirect=1&filters=<url-encoded JSON>
```

They redirect to the equivalent modern URL, so following an old link and copying from the
address bar propagates the new format. Old links are never rewritten where they are stored,
they just stop spreading. This translation is permanent — do not remove the `GET` handler
on `/set_filters`.

## Filter screens and saved filters

The alert manage page is one *filter screen*; other list screens (the SVS screens, Remediations, File
Collections) are more. Each screen has its own filter names and slugs, its own saved filters and
quick filters, and the permission that reads its data: `alert:read` for this page, `signature:read`
for the SVS samples, `remediation:read` and `file_collection:read` for the Remediations and File
Collections pages.

- **Saved filters** are rows of `saved_filters`, keyed by screen, served by
  `/api/v2/saved-filters?screen=<name>`. Every route there requires the screen's permission; a
  route that names a row by uuid checks the permission of the row's own screen. A request that
  names no registered screen (an unknown screen or row) is a 404 only to a caller who may use
  some screen, and a 403 to anyone else. Rows are private to their owner.
- **The screen itself** is described by `GET /api/v2/filter-screens/<name>`: every filter's
  name and slug, and, for a screen built as a shell over the API, how a generic editor edits it
  (`kind`: `text`, `multi`, `date_range` or `bool`, and a `multi` field's `options`). This page
  has its own editor and describes none.
- **Share links** are encoded and decoded by `POST /api/v2/filter-screens/<name>/encode` (a
  filter list in, the `f` values out, refusing a filter the screen would refuse) and
  `GET /api/v2/filter-screens/<name>/decode?f=...` (unknown slugs skipped with a warning, as on
  this page). The encoding exists once, in `saq/gui/filter_url.py`; no page reimplements it in
  JavaScript.

In the GUI, `static/js/saved_filters.js` is the saved-filter component: the Save Filter and
Manage Filters dialogs (`templates/saved_filters/_modals.html`), Save as, Save, delete, quick
filter order and copy link, all through the API. A page hands it the filter list to save, so
what is saved is exactly what the page shows. This page then selects the saved filter through
`POST /ace/select_filter/<uuid>`, because which filter an analyst has selected is Flask session
state; a screen that keeps its state in the URL instead (the other screens) has no session state
and no `working`/`temp` rows.

A screen built as a shell over the API uses `static/js/filter_list_page.js` (`FilterListPage`)
for the whole list: the filter bar, a generic editor built from the screen's descriptor, quick
filters, the table with its sort headers, keyset paging, and an export menu. Everything a reader
can share is in the page URL (`f`, `sort`, `desc`, `limit`, and `saved` for the open saved
filter), so back and forward work and a copied address bar is a share link. The URL's `f` values
go to the list API as they are; the controller decodes them only to show them, and encodes the
editor's filters, through the routes above. *Signatures → Samples* was the first such screen;
Validations, Remediations and File Collections followed. A page can also ask for a checkbox per row
(`select`) for actions on the selected rows.

## For developers

- Grammar and codec: `saq/gui/filter_url.py`
- Slug registry and the frozen legacy alias map: `saq/gui/filter_names.py`
- Screens: `saq/gui/filter_screens.py`. A `FilterScreen` is one list screen with filters
  (`alerts` is this page): its entry model (which names and values it accepts, see
  `saq/gui/filter_entry.py`), its slugs and its pair filters. The codec takes a screen
  (default `alerts`), and `saved_filters` rows carry one, so names, the `working`/`temp`
  scratch rows and quick filters are all per screen. The saved-filter API takes `?screen=`,
  and a screen names the permission it requires (`FilterScreen.permission`) and, optionally,
  the fields a generic editor builds from (`FilterScreen.fields`).
- API callers decode with `decode_filter_query(..., strict=True)`, which rejects an unknown
  slug instead of warning: there is no banner to show the warning on.
- Filter classes and the query they build: `saq/gui/filter_query.py` (Flask-free, so the search
  API runs the same filters)
- The search box's grammar over the same slugs: `saq/search/syntax.py`
- Relative-time parser: `saq/util/relative_time.py`

The `Observable`, `Observable Pattern`, `Tag`, `Analysis` and `Detection Point` filters are **EXISTS subqueries over
their mapping tables, in both directions**, correlated to the entity the caller selects
(`create_filter(..., entity=)`: `GUIAlert`, `Alert` or an alias of either). Inverted, that is the only form that is true for an alert with no matching rows
at all -- a `NOT` evaluated against a joined row cannot be. Non-inverted it avoids the row
fan-out, which is what lets two `observable` filters mean "carries both".

The `Remediation` filter gives every alert exactly one state per source, never NULL, so its
inverted form is `NOT`. It is the column's rule written again in SQL (`remediation_filter_value()`
next to `RemediationCoverage.filter_value` in `saq/remediation/coverage.py`), because the column
computes it in Python for one page of alerts and the filter has to run over all of them. Two
uncorrelated subqueries (`has_remediation_activity()`) answer `none` for an alert with no
remediation activity before the rest runs; the rest is one aggregate over the alert's email
targets. `test_the_filter_agrees_with_the_column` runs every coverage scenario through both, for
`Any` and for one source, so change them together.

**Slugs are a permanent contract.** Never rename or repurpose one; a link written today has
to mean the same thing in five years. Adding new slugs is fine.

The same rule covers `LEGACY_FILTER_NAME_ALIASES`, which maps the *display names* embedded
in pre-3.1 links. It is append-only: renaming a filter in the GUI is safe only because the
modern URL format never contains a display name.
