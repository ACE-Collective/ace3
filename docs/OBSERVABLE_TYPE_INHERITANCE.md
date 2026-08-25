# Observable type inheritance

Every observable in ACE has a type — `email_address`, `url`, `fqdn`, `file`,
and so on. As of PR #193, observable types can declare a parent type, forming
an inheritance hierarchy. Anywhere ACE asks "is this an `email_address`?", the
answer is now yes for `email_address` itself *and* for every type that
**extends** it (`email_from`, `email_return_path`, `email_to`, ...).

A type's parent is declared in YAML:

```yaml
types:
  email_from:
    extends: email_address
    default_display_type: "Mail From"
    description: "email From: header address"
```

The hierarchy is consulted at three points in ACE:

1. **Analysis-module dispatch.** A module declaring
   `valid_observable_types = F_EMAIL_ADDRESS` automatically also runs on every
   subtype of `email_address`.
2. **`observable_modifier` rule matching.** A rule with
   `observable_types: [email_address]` matches every subtype too.
3. **Display labels.** When no code explicitly sets `obs.display_type = "..."`,
   the observable falls back to the `default_display_type` configured for its
   type in YAML.

## `etc/observable_types.yaml` is the source of truth

> **Read this carefully.** Everything ACE knows about its built-in observable
> types — descriptions, deprecation flags, default display labels, and the
> inheritance hierarchy — now lives in `etc/observable_types.yaml`. The
> `F_*` Python string constants in `saq/constants.py` are kept as named
> imports for code, but **all metadata about a type lives in the YAML**, not
> in Python.

### Overriding the file in a deployment

The path is configured by `observable_types.config_path` in
`etc/saq.default.yaml`, and defaults to `etc/observable_types.yaml`.
Production deployments typically override this to a single file of their own
(for example, a file under `signatures/analyst_data/`).

**Important gotcha:** there is no multi-path layering today. A deployment
override **replaces** the built-in file rather than layering on top of it.
If you provide your own observable types YAML, copy `etc/observable_types.yaml`
as a starting point and add your customizations on top — otherwise you will
lose every built-in type entry.

If `observable_types.config_path` is set to an empty string, no YAML is loaded
and the registry stays empty. In that mode, `is_subtype` returns true only for
the self-comparison and there are no default display labels — useful for
isolating tests, but not a normal operating mode.

### Picking up changes at runtime

Registry accessors stat the configured YAML on a debounce and reload it if
the file's mtime has advanced. So edits to the file on disk — for example, a
`git pull` of the signatures repo bringing in a new entry — get picked up by
every running ACE process within a bounded window without an operator
restarting any container.

The cadence is controlled by `observable_types.reload_check_interval_seconds`
in `etc/saq.default.yaml` (default `60.0`). The check is debounced
per-process: at most one `os.stat()` call per worker per interval, regardless
of accessor call rate. A reload that fails (missing file, malformed YAML,
introduces a cycle) leaves the prior in-memory state intact and logs an
error.

Set `reload_check_interval_seconds` to `0` (or any non-positive value) to
disable runtime reload entirely — the registry then loads once at startup
and never refreshes, matching the behavior before this feature shipped.

The `/observable_types/` API endpoint applies its own short TTL cache
(60s by default) on top of the registry, so worst-case staleness for an
analyst hitting the GUI's observable picker is approximately
`reload_check_interval_seconds + cache TTL`. Module dispatch, `display_type`
fallback, and `observable_modifier` rule matching skip the cache layer and
see changes within the reload interval alone.

## Why we built it

### The Mail From / Mail Return Path collision

ACE deduplicates observables by `(type, value)`. Before this change, every
email-address-shaped piece of an email — `From`, `To`, `Cc`, `Reply-To`,
`Return-Path`, the SMTP envelope addresses, and the various `X-*` sender
headers — was added as type `email_address`. When a sender used the same
address in their `From` and `Return-Path` headers (which is very common), the
two were collapsed into a single observable, and analysts lost the ability to
see and act on the Return-Path signal independently.

The fix introduces 11 distinct email subtypes, all extending `email_address`.
Now `Mail From` and `Mail Return Path` carry distinct types and dedup never
collapses them, regardless of value. See the *email subtype tree* further
down.

### Metadata sprawl

Before this change, type metadata lived in three different blocks of
`saq/constants.py` (`OBSERVABLE_DESCRIPTIONS`, `VALID_OBSERVABLE_TYPES`,
`DEPRECATED_OBSERVABLES`) and dozens of `obs.display_type = "..."` setters
sprinkled across email-parsing code. Adding or deprecating a type meant
editing several places at once, and no single source listed every type ACE
knew about. The YAML registry consolidates all of it.

### Module-author burden

When a new email-address-shaped type was needed (for example, a vendor-
specific header), every module that already ran on `email_address` had to be
updated by hand to add the new type to its `valid_observable_types`. Subtype-
aware dispatch removes that step entirely.

## What it lets you do

### Distinguish observables that share a value but mean different things

When an email's `From` and `Return-Path` headers both contain
`alice@example.com`, you now get two observables — one of type `email_from`
with display label `Mail From`, and one of type `email_return_path` with
display label `Mail Return Path` — instead of one collapsed observable. The
same applies across all 11 email subtypes (see the tree below).

### Write analysis modules that target a parent type

A module that wants to run on every email address — regardless of which header
it came from — only has to declare the parent type:

```python
from saq.constants import F_EMAIL_ADDRESS

class MyEmailAddressModule(AnalysisModule):
    @property
    def valid_observable_types(self):
        return F_EMAIL_ADDRESS
```

This module will be dispatched against every observable whose type *is or
extends* `email_address` — including all the new email subtypes, plus any new
ones added later in YAML. No code changes required when a new subtype lands.

If a particular module genuinely requires an exact-type match (for example,
something that should only ever run on the bare `email_address` and never on
the subtypes), set `valid_observable_subtypes = False` on the class:

```python
class StrictEmailAddressModule(AnalysisModule):
    valid_observable_subtypes = False

    @property
    def valid_observable_types(self):
        return F_EMAIL_ADDRESS
```

### Write `observable_modifier` rules that target a parent type

The `observable_modifier` rule conditions are subtype-aware too. A rule like:

```yaml
- name: tag_internal_email_addresses
  conditions:
    observable_types: [email_address]
    value_regex: "@example\\.com$"
  actions:
    add_tags: [internal]
```

…matches `email_address` *and* every subtype (`email_from`,
`email_return_path`, `email_to`, `email_cc`, etc.) without listing them
individually. If you want a rule that only runs on a specific subtype — say,
only on Return-Path observables — list that subtype explicitly:

```yaml
conditions:
  observable_types: [email_return_path]
```

### Define new observable types in YAML without writing Python

Adding a new entry to `etc/observable_types.yaml` (or your deployment's
override file) is enough to make a type fully real:

```yaml
types:
  pdf_file:
    extends: file
    description: "PDF document"
```

Once the change is on disk and the runtime-reload window has elapsed
(see *Picking up changes at runtime* above):

- `pdf_file` is reported by `get_all_valid_types()` and accepted by the `ace`
  CLI's `add-observable` command and the `/observables/types` API.
- Any analysis module declaring `valid_observable_types = F_FILE` will also
  run on `pdf_file` observables.
- Any `observable_modifier` rule targeting `file` will also match `pdf_file`.
- The description shows up in API responses and in the analyst UI's
  observable picker.
- Adding `deprecated: true` on a future date hides it from pickers without
  removing the entry.

The `F_*` Python constant is only required if Python code needs to reference
the type by symbolic name. Hunt rules and observable-modifier rules can refer
to the YAML name directly.

### Get consistent display labels for free

Before this change, getting "Mail Return Path" to appear in the UI for a
Return-Path observable required Python code to call
`obs.display_type = "Mail Return Path"` at every site that created the
observable. Now, setting:

```yaml
email_return_path:
  extends: email_address
  default_display_type: "Mail Return Path"
```

…is enough. Every observable of type `email_return_path` automatically
displays as `Mail Return Path (email_return_path)` unless code explicitly
overrides `display_type`. Explicit setters still win — the YAML default is
only consulted when no setter has run.

## Observable Detections

ACE has the ability to mark observables for detection such that ACE will add a detection point whenever the observable is seen. It's worth noting the difference in how that detection works between ACE itself and the external systems that ACE exports these observables to.

ACE will add a detection point when the observable **and the type** match exactly.

When ACE exports observable detection information into external systems, it **collapses the type to the parent type**. For example, observables with the type `email_reply_to` that are enabled for detection are exported as the `email_address` observable type.

ACE often understands the context of observations because it did the analysis/parsing. In the case of external systems, this isn't always the case. For example, yara rules scan entire blobs of data, so the context of an email address being used as the reply-to is not available.

## The email subtype tree

All 11 new email subtypes extend `email_address`. The display labels listed
here are configured via `default_display_type` in `etc/observable_types.yaml`
and are what analysts see in the UI.

```
email_address
├── email_from                      ─ "Mail From"
├── email_to                        ─ "Mail To"
├── email_cc                        ─ "Mail CC"
├── email_reply_to                  ─ "Mail Reply To"
├── email_return_path               ─ "Mail Return Path"
├── email_envelope_mail_from        ─ "Envelope Mail From"
├── email_envelope_rcpt_to          ─ "Envelope Recipient"
├── email_x_sender                  ─ "Mail X-Sender"
├── email_x_sender_id               ─ "Mail X-Sender ID"
├── email_x_auth_id                 ─ "Mail X-Auth ID"
└── email_x_original_sender         ─ "Mail X-Original Sender"
```

`email_conversation`, `email_delivery`, `email_subject`, `email_header`,
`email_body`, `email_x_mailer`, and `message_id` are *not* subtypes of
`email_address`; they remain top-level types because their values are not
email addresses.

## Where to look in code

| Concern                                  | File                                                                                            |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Built-in YAML                            | `etc/observable_types.yaml`                                                                     |
| Config knob (`observable_types.config_path`) | `etc/saq.default.yaml`                                                                          |
| Registry implementation                  | `saq/observables/type_hierarchy.py` (`get_type_hierarchy()`, `get_all_valid_types()`)           |
| Module dispatch (subtype-aware)          | `saq/modules/base_module.py` (`AnalysisModule.accepts`, `valid_observable_subtypes`)            |
| Display-label fallback                   | `saq/analysis/observable.py` (`Observable.display_type`)                                        |
| `observable_modifier` rule matching      | `saq/modules/util/observable_modifier.py` (`RuleConditions.evaluate`, `evaluate_early`)         |
| Detection export type selection          | `saq/observables/export/base.py` (`select_detections`), used by the yara and splunk targets      |
| Bootstrap at startup                     | `saq/environment.py` (`initialize_environment` calls `bootstrap_type_hierarchy`)                |
