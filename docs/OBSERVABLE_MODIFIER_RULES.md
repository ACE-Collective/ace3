# Observable Modifier Rules

- [Overview](#overview)
  - [Why this is powerful: toxic-combination detections](#why-this-is-powerful-toxic-combination-detections)
  - [Where rules live](#where-rules-live)
  - [How a rule is structured](#how-a-rule-is-structured)
    - [uuid (required)](#uuid-required)
    - [enabled](#enabled)
  - [Conditions](#conditions)
    - [Alert-level conditions](#alert-level-conditions)
    - [Observable-level conditions](#observable-level-conditions)
    - [Tree conditions](#tree-conditions)
  - [Actions](#actions)
  - [Phases: pre vs post](#phases-pre-vs-post)
    - [Which to use](#which-to-use)
  - [When a rule matches](#when-a-rule-matches)
  - [Worked examples](#worked-examples)
  - [Quick reference: writing a new rule](#quick-reference-writing-a-new-rule)

## Overview

The **Observable Modifier** is an analysis module that lets analysts change how ACE treats an
observable *without writing code*. You write declarative rules in a YAML file; ACE evaluates every
rule against every observable in an alert, and when a rule's conditions match, it applies that
rule's actions to the observable.

Think of it as a rules engine layered on top of the analysis tree. It can:

- **add detection points based on the content or structure of the alert** — the headline
  capability: this particular thing might be benign by itself, but combined with some other thing
  it forms a "toxic combination" worth alerting on. See
  [Why this is powerful](#why-this-is-powerful-toxic-combination-detections) below.
- add **directives** that turn downstream analysis on or off (e.g. `crawl`, `ocr`, `extract_iocs`,
  `pivot_on_ip`)
- add **tags**
- **exclude**, **limit**, or **reset** specific analysis modules for an observable
- **ignore** an observable entirely — removing it from the alert
- override an observable's **display type / value** in the GUI

Source: `saq/modules/util/observable_modifier.py`

### Why this is powerful: toxic-combination detections

Most detection logic in ACE is *local*. A yara rule sees one file. An analysis module sees the one
observable it was handed plus whatever it produces. None of them has a vantage point over the
*whole alert*. That makes a certain class of detection awkward to express: the kind where no single
fact is bad, but a *specific combination of facts* — drawn from different files, different
observables, different analysis modules — is exactly the pattern an attacker leaves behind.

The Observable Modifier is the one place in ACE where a rule is evaluated **with the entire
analysis tree in view**. Through `tree_conditions` it can reach up to ancestors, down to
descendants, sideways to siblings, or across the whole tree, and ask "is *this* analysis also
present, with *these* details?" That is what turns it from a tagging utility into a correlation
engine.

Why that matters in practice:

- **It detects what individual signals are deliberately tuned not to.** A QR code in an email isn't
  an alert. A message from a bulk email service isn't an alert. A `new_sender` tag isn't an alert.
  Each of those, on its own, would drown analysts in false positives — so they're intentionally
  kept quiet. But *QR code + bulk sender + new sender together* is a phishing pattern worth
  surfacing. The Observable Modifier lets you keep every individual signal benign while still
  alerting on the toxic intersection.
- **It expresses cross-cutting logic that would otherwise require a new analysis module.** Without
  this system, "alert when an email contains a nested `.eml` whose inner sender claims one of our
  domains but the outer sender is external and the inner message has no `message-id`" would mean
  writing, testing, and deploying Python. As a rule it's four `tree_conditions` in a YAML file. No
  code, no deployment — and it's **hot-reloaded**, so you can codify a campaign pattern the same
  day you observe it.
- **It correlates facts that live in different branches of the tree.** A URL observable doesn't
  know its domain's WHOIS age — that fact lives on a *descendant* FQDN's `WhoisAnalysis`. It
  doesn't know the email body tripped a yara rule — that's a `signature_id` observable somewhere
  else entirely. `tree_conditions` with `descendants`, `siblings`, and `global` scope let one rule
  stitch those separate facts into a single decision.
- **Detections compose.** Because every match emits a `signature_id` observable, one rule's output
  becomes another rule's input. You can build a low-noise primitive signal as one rule and then
  write higher-confidence rules that fire only when that primitive *and* additional context are
  both present — layered detection assembled entirely from declarative rules.
- **It puts detection engineering in analysts' hands.** The analyst who sees the campaigns can
  encode the "if I see X and Y together, that's bad" intuition directly.

The trade-off is cost: `tree_conditions` are the most expensive conditions to evaluate (tree
walks, and `details_match` forces analysis details to load from disk). Put cheap observable-level
conditions first so a rule short-circuits before it ever walks the tree — see
[Conditions](#conditions).

### Where rules live

Rules are defined in a single YAML file. The path is set by the module config key
`rules_config_path` and defaults to `etc/observable_modifier_rules.yaml` (relative to `SAQ_HOME`).
A deployment can point this key at a different file (for example, a separate signatures repository)
without changing any code.

The file is **watched** — edits are picked up automatically without restarting ACE. A rule that
fails to parse (bad regex, missing `uuid`, etc.) is logged and skipped; the rest of the file still
loads.

### How a rule is structured

```yaml
rules:
  - name: "Human-readable rule name"
    uuid: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   # REQUIRED — see below
    description: "Optional free text explaining intent"
    enabled: true                                   # default true
    phase: pre                                      # "pre" or "post" (default post)

    conditions:
      # ... all optional, AND-ed together ...

    actions:
      # ... one or more actions to apply when conditions match ...
```

#### uuid (required)

Every rule needs a stable UUID. Generate one with `uuidgen` or
`python -c "import uuid; print(uuid.uuid4())"`. A rule with no `uuid` is **refused at load time**.

The UUID is not just an identifier — whenever the rule matches, ACE emits a `signature_id`
observable with that UUID. This means analysts can search the GUI for *every alert where a specific
rule fired*, and rules can even reference each other (one rule's tree condition can check for
another rule's `signature_id`).

#### enabled

Set `enabled: false` to turn a rule off without deleting it.

### Conditions

All condition fields are optional. Within a single rule, **every** specified condition must pass
(AND logic). Rules are evaluated independently of one another.

#### Alert-level conditions

| Field | Meaning |
|-------|---------|
| `alert_tags: [a, b]` | Alert must have **all** of these tags |
| `alert_type: "..."` | Alert type must equal this string exactly |
| `queue: "..."` | Alert queue must equal this string exactly |

#### Observable-level conditions

| Field | Meaning |
|-------|---------|
| `observable_types: [file, url]` | Observable type must be one of these. **Subtype-aware** — a rule targeting `email_address` also matches `email_from`, `email_return_path`, etc. |
| `value_pattern: "regex"` | Regex search against the observable's value |
| `file_name_pattern: "regex"` | Regex search against the file name (file observables only) |
| `display_type_pattern: "regex"` | Regex search against the observable's display type |
| `display_value_pattern: "regex"` | Regex search against the observable's display value |
| `has_tags: [a, b]` | Observable must have **all** of these tags |
| `has_directives: [a, b]` | Observable must have **all** of these directives |
| `has_yara_meta_tags: ["type=..."]` | Observable must carry **all** of these yara-meta directives |

> Regex values are standard Python `re` patterns. Remember YAML escaping — a literal `.` in a
> pattern is `\\.` in the YAML file. Case-insensitive matching is done with an inline `(?i)` flag.

#### Tree conditions

The most powerful (and most expensive) conditions inspect the **analysis tree** — the graph of
analyses and observables ACE builds while working an alert. A tree condition asks: *"is there an
analysis of type X somewhere relative to this observable, optionally matching some details?"*

```yaml
tree_conditions:
  - analysis_type: "saq.modules.email.rfc822:EmailAnalysis"
    scope: ancestors            # see scopes below
    negate: false               # invert the result of this one condition
    match_count: 1              # optional — require exactly N matches (default ≥1)
    details_match:
      email.from_address: "soc@third-party.com"   # dot-notation path, regex value
    observable_match:
      file_name: ".*\\.html$"   # regex against the matching analysis's observable
                                # (supported props: type, value, file_name)
    produces_observable_type: "url"               # matched analysis must have PRODUCED this type
    produces_observable_value: ".*example\\.com"  # optional regex on the produced observable's value
```

`scope` controls *where* ACE looks, relative to the observable being evaluated:

| Scope | Looks at |
|-------|----------|
| `ancestors` (default) | Every analysis above this observable in the tree |
| `descendants` | Analyses on observables produced transitively *below* this one |
| `parent` | Only the analyses that directly produced this observable |
| `siblings` | Analyses on the observable(s) that directly produced this one — i.e. peer analyses (e.g. the `FileTypeAnalysis` on the file that yielded this URL) |
| `self` | Analyses attached to this observable itself |
| `global` | Every analysis in the entire alert tree |

`negate: true` flips that single condition — useful for "...and is NOT a descendant of
PhishkitAnalysis".

`match_count` requires *exactly* that many matching analyses. Omitted means "at least one".
`match_count: 1` on an `ancestors` scope is a common way to scope a rule to a top-level context
(e.g. "exactly one EmailAnalysis ancestor" = a top-level email observable, not a nested one).

`details_match` loads the analysis's details and regex-matches values at a dot-notation path (e.g.
`email.from_address`, `age_created_in_days`, `mime`). If a key along the path resolves to a list,
the remaining path is applied to each element and the condition matches if *any* element matches.

`observable_match` regex-matches properties of the *matching analysis's* observable (e.g. `type`,
`value`, `file_name`).

> Careful when combining `observable_match` with `negate: true`. If the named property does not exist
> on the observable at all — `file_name` on a `url`, say — the property check fails, the analysis is
> not counted as a match, and `negate` turns that into "condition passed." An analyzer that runs on
> more than one observable type will therefore slip through a negated `observable_match` written for
> only one of them. Match on a property the observable type actually carries, or drop
> `observable_match` and tighten the `scope`/`analysis_type` instead.

`produces_observable_type` requires the matching analysis to have **produced** an observable whose
type is a subtype of the given type. Unlike `observable_match` (which inspects the analysis's *own*
observable), this inspects the observables the analysis *generated*. `produces_observable_value` is
an optional regex applied to that produced observable's value.

> Note: when a `descendants`-scoped condition specifies only `observable_match` (no `analysis_type`
> and no `details_match`), ACE matches against descendant *observables* directly rather than the
> analyses on them — useful for "does any observable below me look like this?".

### Actions

When all conditions pass, every action below that is present gets applied.

| Action | Effect |
|--------|--------|
| `add_directives: [crawl, ocr]` | Add directives to the observable. Directives gate downstream analyzers — this is how you turn analysis on. |
| `add_tags: [phish:EvilTokens]` | Tag the observable. |
| `add_detection_points: ["..."]` | Add a detection point — this is what makes an alert *alert*. The string is the analyst-facing description. |
| `exclude_analysis: ["module.path:AnalyzerClass"]` | Prevent a module from running on the observable. Names the **Analyzer class**. |
| `limit_analysis: ["short_module_name"]` | Restrict the observable to only the listed modules. Uses the **short module name** from the engine config (`module_config.name`), not a `path:Class` string. |
| `reset_analysis: ["module.path:AnalysisClass"]` | Clear the "no analysis" sentinel a module recorded, giving it a second pass. Names the **Analysis class**. Must run in `post` phase. |
| `set_display_type: "Phishing URL"` | Override the observable's display type in the GUI. |
| `set_display_value: "decoded payload"` | Override the observable's display value in the GUI. |
| `ignore: true` | Remove the observable from matching parent analyses (and from the DB if no parents remain). In `pre` phase it also installs `exclude_all` so ACE skips all further work on it. |

> **Naming gotcha:** `exclude_analysis` names the *Analyzer* class (`...:SandboxAnalyzer`),
> `reset_analysis` names the *Analysis* class (`...:PhishkitAnalysis`), and `limit_analysis` uses
> the short config name (`ioc_extraction`). These come from three different lookup mechanisms in
> the engine — copy the form from an existing rule when in doubt.

### Phases: pre vs post

Each rule runs in one of two phases:

- **`pre`** — evaluated in `execute_analysis`, which is **re-invoked repeatedly** as the analysis
  tree grows. Directives added here can take effect *inline*, so the modules they gate run during
  the same alert pass instead of waiting.
- **`post`** — evaluated once in `execute_final_analysis`, after the engine has drained all
  analysis.

The default phase is `post`. (An unrecognized `phase:` value is logged as a warning and treated as
`post`.)

#### Which to use

Prefer `pre`, unless one of these hard constraints applies:

1. **The action is `reset_analysis`** → must be `post`. `reset_analysis` clears a "no-analysis"
   sentinel a target module records *after* it evaluates and bails. In `pre` the target hasn't run
   yet — there's no sentinel to clear.
2. **A tree condition gates on a slow/deferred field** (WHOIS domain age, sandbox results, modules
   with long backoff, yara-emitted `signature_id` observables) → use `post`. Pre-phase rules get no
   final pass, so a condition that only becomes true after the engine drains would be missed.

`pre` is especially valuable when the rule installs directives (`crawl`, `ocr`, `extract_iocs`,
`pivot_on_ip`) that gate downstream analyzers — in `pre` those modules run inline. Tree-condition
*scope* is **not** the deciding factor; `descendants` and `global` rules work fine in `pre` because
`execute_analysis` is re-invoked as the tree grows.

The failure modes are asymmetric: a rule that should be `post` but is marked `pre` may **silently
miss matches**; a rule that should be `pre` but is marked `post` just **fires later than
necessary**.

`ignore: true` works in both phases; `pre` is preferred because the observable is removed *and*
excluded from all further analysis, rather than fully analyzed and then discarded.

### When a rule matches

Whenever a rule matches an observable, ACE:

1. applies the rule's actions to that observable;
2. records the match in an **Observable Modifier Analysis** attached to the observable, with a
   summary like *"Applied 2 rule(s): ..."* and the list of actions actually applied;
3. emits a `signature_id` observable carrying the rule's `uuid` (deduplicated, so a rule that
   matches in both phases emits it only once).

### Worked examples

The examples below are illustrative — they mirror the structure of real production rules but use
generic names, domains, and UUIDs. The field names, scopes, actions, and module paths reflect the
current implementation.

#### 1. Turn on IOC extraction for a specific alert type

The simplest shape — alert-type + file-name filter, one directive.

```yaml
- name: "Vendor escalation IOC extraction"
  uuid: "11111111-1111-1111-1111-111111111111"
  phase: pre
  conditions:
    alert_type: "hunter - splunk - vendor_escalation"
    observable_types: [file]
    file_name_pattern: '\.rfc822\.unknown_text_html_000(\.\w+)?$'
  actions:
    add_directives: [extract_iocs]
```

*"For vendor escalation alerts, run IOC extraction on the email's HTML body file."* `pre` so
extraction runs inline.

#### 2. Add a detection point from a tree relationship

A value regex plus a tree condition — fire a detection when a URL extracted from a QR code targets
an employee.

```yaml
- name: "QR code URL targeting employee"
  uuid: "22222222-2222-2222-2222-222222222222"
  phase: pre
  conditions:
    observable_types: [url]
    value_pattern: '(?i)@(example\.com|corp\.example\.com)'
    tree_conditions:
      - analysis_type: "saq.modules.file_analysis.qrcode:QRCodeAnalysis"
        scope: "ancestors"
  actions:
    add_detection_points: ["QR code URL targeting employee"]
```

The URL only counts if it descended from a `QRCodeAnalysis` — i.e. it came out of a scanned QR
code, not from email body text.

#### 3. negate scope — conditional enabling

Enable OCR on images, but *not* on phishkit screenshots or embedded data-URL files.

```yaml
- name: "Enable OCR for images"
  uuid: "33333333-3333-3333-3333-333333333333"
  phase: pre
  conditions:
    observable_types: [file]
    has_yara_meta_tags: ["type=image"]
    tree_conditions:
      - analysis_type: "saq.modules.phishkit:PhishkitAnalysis"
        scope: "parent"
        negate: true
      - analysis_type: "saq.modules.file_analysis.html:HTMLDataURLAnalysis"
        scope: "ancestors"
        negate: true
  actions:
    add_directives: ["ocr"]
```

Three conditions, AND-ed: *is* an image (per the `type=image` yara-meta tag), is *not* a phishkit
screenshot, and is *not* an embedded data-URL file.

The phishkit condition uses `parent` scope rather than `ancestors` because it should match the files
phishkit itself produced, not everything downstream of a phishkit scan. Phishkit's only image output
is the screenshot, so `type=image` + "produced directly by `PhishkitAnalysis`" identifies screenshots
exactly — whether phishkit scanned a URL or rendered an HTML body. Note what *doesn't* work here:
adding `observable_match: {file_name: ...}` to narrow the condition to a particular scanned file
would silently stop excluding screenshots from URL scans, since a `url` observable has no
`file_name` and `negate` turns that failed property check into "condition passed."

#### 4. ignore with parent scope — surgically drop an observable

Remove internal security-team addresses from the *envelope recipient* context, while preserving the
same address if it shows up via IOC extraction.

```yaml
- name: "Ignore vendor escalation team email addresses"
  uuid: "44444444-4444-4444-4444-444444444444"
  phase: pre
  conditions:
    alert_type: "hunter - splunk - vendor_escalation"
    observable_types: [email_address, email_conversation, email_delivery]
    value_pattern: '(?i)(alice|bob|carol)@example\.com'
    tree_conditions:
      - analysis_type: "saq.modules.email.rfc822:EmailAnalysis"
        scope: "parent"
  actions:
    ignore: true
```

Because the tree condition is `parent`-scoped, `ignore` only detaches the observable from the
`EmailAnalysis` that produced it — other references survive.

#### 5. post phase with reset_analysis — gating on slow analysis

Crawl a URL whose domain WHOIS/RDAP shows it was registered in the last 7 days.

```yaml
- name: "Crawl newly registered domain URL in email"
  uuid: "55555555-5555-5555-5555-555555555555"
  phase: post
  conditions:
    observable_types: [url]
    tree_conditions:
      - analysis_type: "saq.modules.email.rfc822:EmailAnalysis"
        scope: "ancestors"
      - analysis_type: "saq.modules.rdap:RdapAnalysis"
        scope: "descendants"
        details_match:
          age_created_in_days: '^[0-7]$'
  actions:
    add_directives: [crawl]
    reset_analysis: ["saq.modules.phishkit:PhishkitAnalysis"]
    add_detection_points: ["Newly registered domain (within 7 days) in email URL"]
```

`post` because the domain-age lookup is a deferred analysis. `reset_analysis` clears the sentinel
phishkit recorded when it first saw the URL with no `crawl` directive, so phishkit gets a second
pass and actually crawls.

#### 6. siblings scope — consult a peer analysis

Crawl URLs pulled from an iCalendar file. The URL observable can't see the file's MIME type
directly, but it can consult the `FileTypeAnalysis` on its sibling — the `.ics` file that produced
it.

```yaml
- name: "Crawl URLs extracted from iCalendar files"
  uuid: "66666666-6666-6666-6666-666666666666"
  phase: pre
  conditions:
    observable_types: [url]
    tree_conditions:
      - analysis_type: "saq.modules.file_analysis.file_type:FileTypeAnalysis"
        scope: siblings
        details_match:
          mime: '^text/calendar$'
  actions:
    add_directives: [crawl]
```

#### 7. Cross-rule reference via signature_id

This rule gates on another rule/signature's output: it only fires if a yara rule (itself emitted as
a `signature_id`) matched somewhere in the tree.

```yaml
- name: "URL in email uses newly registered domain"
  uuid: "77777777-7777-7777-7777-777777777777"
  phase: post
  conditions:
    observable_types: [url]
    tree_conditions:
      - analysis_type: "saq.modules.email.rfc822:EmailAnalysis"
        scope: "ancestors"
      - analysis_type: "saq.modules.nrd:NRDAnalysis"
        scope: "self"
      - scope: "global"
        observable_match:
          type: "signature_id"
          value: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"   # uuid of the depended-on signature
  actions:
    add_directives: [crawl]
    reset_analysis: ["saq.modules.phishkit:PhishkitAnalysis"]
    add_detection_points: ["URL in email uses newly registered domain"]
```

The third tree condition uses `global` scope + `observable_match` to ask "did a `signature_id`
observable with this value appear *anywhere* in the alert?" — a general pattern for "this rule
depends on that signature having fired." (Note the empty `analysis_type` on that condition: when it
is omitted, ACE matches on `observable_match` alone.)

#### 8. exclude_analysis — suppress noisy downstream work

Don't bother extracting and analyzing FQDNs from our own email addresses.

```yaml
- name: "Skip FQDN extraction for our own e-mail addresses"
  uuid: "88888888-8888-8888-8888-888888888888"
  phase: pre
  conditions:
    observable_types: [email_address]
    value_pattern: '(?i)@(example\.com|corp\.example\.com)$'
  actions:
    exclude_analysis: ["saq.modules.email.address:EmailAddressFQDNAnalyzer"]
```

### Quick reference: writing a new rule

1. **Generate a UUID** — `uuidgen` — and put it in the `uuid` field.
2. **Give it a clear `name` and a `description`** explaining *why* it exists; the production file's
   descriptions double as the design rationale.
3. **Pick conditions** — start with the cheapest (`observable_types`, `value_pattern`,
   `alert_type`) and add `tree_conditions` only when you need tree context. All conditions in a
   rule are AND-ed.
4. **Pick actions** — mind the three naming conventions for `exclude_analysis` /
   `reset_analysis` / `limit_analysis`.
5. **Choose a phase** — default to `pre`; switch to `post` only if you use `reset_analysis` or gate
   on a slow/deferred analysis or a yara-emitted `signature_id`.
6. **Save the file** — it's hot-reloaded. Check the logs for parse warnings.
7. **Verify** — once the rule fires, the observable gets an *Observable Modifier Analysis* node,
   and you can search the GUI for the rule's `uuid` as a `signature_id`.
