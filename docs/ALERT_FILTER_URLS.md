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
| `unconfirmed_detections` | Unconfirmed Detections | | | |

`unconfirmed_detections:True` finds alerts with a detection whose verdict nobody has confirmed: an
inherited TP on a TP alert where several signatures fired (`docs/SVS.md`, Part 1); `False` the rest.

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

`GET /api/v2/alerts` (permission `alert:read`) lists alerts as flat database rows for export
and reporting, and takes these filters as repeated `f` query parameters, exactly as written in
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

## The same slugs in the search box

The manage-page search box understands these slugs too, so `queue:default` means the same
thing typed as it does in a link (`docs/SEARCH.md`, section 2). It is a sibling grammar, not
the same one, and it differs in three ways on purpose:

- **Values are literal.** A link is generated, so it percent-encodes `:`, `,` and `%`; a search
  box is typed, so it must not demand that. Quote instead: `url:"https://evil.com/a,b"`.
- **`-` also inverts**, alongside `!`, because `!` is awkward in a shell.
- **Any observable type is a prefix of its own**: `ipv4:1.2.3.4` is shorthand for
  `observable:ipv4:1.2.3.4`, and `uuid:` means the *alert* uuid rather than the observable
  type of that name.

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

The alert manage page is one *filter screen*; other list screens (the SVS screens) are more. Each
screen has its own filter names and slugs, its own saved filters and quick filters, and the
permission that reads its data: `alert:read` for this page, `signature:read` for the SVS samples.

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
state; a screen that keeps its state in the URL instead (the SVS screens) has no session state
and no `working`/`temp` rows.

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

The `Observable`, `Tag`, `Analysis` and `Detection Point` filters are **EXISTS subqueries over
their mapping tables, in both directions**, correlated to the entity the caller selects
(`create_filter(..., entity=)`: `GUIAlert`, `Alert` or an alias of either). Inverted, that is the only form that is true for an alert with no matching rows
at all -- a `NOT` evaluated against a joined row cannot be. Non-inverted it avoids the row
fan-out, which is what lets two `observable` filters mean "carries both".

**Slugs are a permanent contract.** Never rename or repurpose one; a link written today has
to mean the same thing in five years. Adding new slugs is fine.

The same rule covers `LEGACY_FILTER_NAME_ALIASES`, which maps the *display names* embedded
in pre-3.1 links. It is append-only: renaming a filter in the GUI is safe only because the
modern URL format never contains a display name.
