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
  **ORed**.
- A leading `!` inverts the filter (`!tag:whitelisted` = alerts *without* that tag).
- Filters are named by a stable **slug**, not by the label shown in the GUI.

| slug | filter | | slug | filter |
|---|---|---|---|---|
| `alert_date` | Alert Date | | `event_date` | Event Date |
| `alert_type` | Alert Type | | `observable` | Observable |
| `description` | Description | | `owner` | Owner |
| `disposition` | Disposition | | `queue` | Queue |
| `disposition_by` | Disposition By | | `reviewed` | Reviewed |
| `disposition_date` | Disposition Date | | `tag` | Tag |

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

## For developers

- Grammar and codec: `saq/gui/filter_url.py`
- Slug registry and the frozen legacy alias map: `saq/gui/filter_names.py`
- Relative-time parser: `saq/util/relative_time.py`

**Slugs are a permanent contract.** Never rename or repurpose one; a link written today has
to mean the same thing in five years. Adding new slugs is fine.

The same rule covers `LEGACY_FILTER_NAME_ALIASES`, which maps the *display names* embedded
in pre-3.1 links. It is append-only: renaming a filter in the GUI is safe only because the
modern URL format never contains a display name.
