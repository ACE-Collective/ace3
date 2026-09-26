# Advanced Correlated Hunting

This proposes to add advanced correlational capabilities to the hunting system. Analysts will have the ability to gather more data into the results of a hunt and then make decisions based on that data.

The following is added to the schema of the hunt YAML definition:

- A new optional field of `correlate` is added to the `rule` definition.
- A new optional top level key of `commands` is available.

## Basic Concept

A hunt generates one or more rows of JSON which flows into a correlation as a list of JSON objects. This is called the `event stream`. Each object is processed by the correlational logic individually. We call the object currently being processed the `event`. Both the stream and the event currently being processed can be modified. The processing of each event can take a different branch through the logic.

By default all events that pass through the logic without being filtered out are passed on as alerts.

### Definitions

- `event`: the current JSON input event being evaluated
- `event_stream`: the input stream of events

## Syntax

### Common Properties

All types can have the following properties.

- `description`: human description for what the block does
- `debug`: a jinja interpolated debug message generated during processing

### Correlate

Top level correlate is the root of this new logic tree.

```yaml
correlate: 
    timeout: 15m # optional (default 15m)
    logic: [ condition | transform | action ] # required
```

The `timeout` specifies the maximum amount of time that can be spent running the correlate logic. The default timeout is 15m.

If this time expires before correlate logic can complete — whether *between events* or *partway through a single event's steps* — a warning is logged (identifying the hunt by name and uuid), a stream-level `timeout` event is recorded, and each affected event's trace outcome is recorded as `timeout`. The affected event's remaining steps are skipped and it falls through to an **alert**: this is a fail-safe, so a timeout can never silently drop an event (and a partially-processed event is never mistaken for one that passed cleanly). If you need different behavior, reduce the work per event (e.g. `cache:` slow commands, run cheap `when` filters before slow transforms) or raise the `timeout` rather than relying on this fall-through.

### Conditions

A condition defines an `expression` and a routing for logic through `execute`.

```yaml
- when: expression | { expression }
  execute: [ condition | transform | action ] # required
  else: [ condition | transform | action ] # optional
```

An `expression` defined as a string is shorthand for defining an expression with all default settings with the `value` set to the value.

If the `expression` evaluates to true (as cast by bool()), then `execute` is executed, otherwise, `else` is executed if defined.

### Expressions

An expression evaluates to true or false.

```yaml
- type: and, or, not, equals, glob, regex, jinja # defaults to jinja
  value: expression | [ expression ] # required
  # optional fields based on the type
  property: the name of a field to compare # required only for equals, glob, regex
  case_sensitive: true | false # optional, only applies to equals, glob, regex, defaults to true
```

The `type` field determines how `value` is evaluated as follows:

- `and`: `value` is a list of `expressions` and returns true if all return true.
- `or`: `value` is a list of `expressions` and returns true if any return true.
- `not`: `value` is a `expression` and returns true if the expression return false. An exception should be raised if `value` is a list in the case of `not`.
- `equals`: the value of `value` is compared directly with target event value
- `glob`: the value of `value` is interpreted as a shell-style globbing pattern against the target event value
- `regex`: the value of `value` is interpreted as a regular expression against the target event value
- `jinja`: the value of `value` is interpolated by the jinja engine and the result is cast to bool

For `equals`, `glob`, and `regex`, the "target event value" is specified by the `property` field. The `case_sensitive` field then controls the case sensitivty of the evaluation.

### transform

Both the `event stream` and the `event` can be transformed. There are two types of transformations that can be done: `stream transformation` and `event transformation`.

A `stream transformation` builds a new event stream from an existing event stream and then resets the processing to the beginning of the new event stream. This means that the current event (and the current event stream) is discarded, and then the **first event** from the new event stream is now the current event. Processing then continues on to the next step after the transform.

```txt
Example: current event stream 0, 1, 2, 3, 4 <-- existing (old) event stream
                                 ^-- current event is event "1"
A stream transformation takes place, returning a new event stream of 0, 1, 2 <-- current event stream is now this new stream
                                                                     ^-- current event is now this one
```

An `event transformation` modifies the event currently being processed.

```yaml
transform:
    type: stream | event # defaults to event
    method: property | merge | mutate # defaults to property
    property_name: any string value # required only for property
    property_type: TYPE # see below, defaults to str
    merge_time_spec: # required only for merge
        l_field: blah # the field that contains the time in the existing data
        l_format: blah # the format of the timestamp
        r_field: blah # the field that contains the time in the new data
        r_format: blah # the format of the timestamp
    command: dict # see below
```

`type` sets the type of transformation to execute

- `event`: executes an event transformation
- `stream`: executes a stream transformation

The `method` controls the method of transformation that is to take place. See Transformation Methods.

The `command` determines the transformation logic to be executed. See Transformation Commands.

#### Transformation Methods

##### property

The `property` method is only valid for an `event transformation` (which is the default type.)

The `property` method adds or modifies the specified field of the current `event` with the contents set to the output of the command. 

The `property_type` controls how the output is interpreted. The possible values for `property_type` are as follows:

- list: Output is interpreted as JSONL. The value of the field is a list of dicts.
- dict: Output is interpreted as JSON. The value of the field is a dict.
- TYPE: Output is passed to TYPE which is a Python supported data type, such as str, int, float, bool, etc... The default value is str.

##### merge

A `merge` is only valid for a `stream transformation`.

The output is assumed to be JSONL. The results are merged into the existing data based on time. The `merge_time_spec` setting controls what fields are interpreted as the time. Incoming events that do not have timestamps are not merged.

##### mutate

A `mutate` is only valid for a `stream transformation`.

The output is assumed to be JSONL. The results replace the existing data.

### Transformation Commands

Every `command` as the following properties available:

```yaml
command:
    type: TYPE # required (see below)
    timeout: 30s # optional (default 10m)
```

The optional `timeout` setting controls how long to wait for the command to complete. If the command does not complete in the time specified, it is canceled (or killed) and treated as an error condition.

### Error handling

If any step fails for any reason — a command exits non-zero, a query source is unreachable, a command times out, an expression raises, an action raises — step processing for the affected event stops immediately and the event is alerted. The event's trace outcome is recorded as `error` and the error message is attached to the failing step's trace so it can be reviewed in the alert UI or CLI trace output.

This is a fail-safe: the correlation pipeline can never silently drop an event as a result of an error. If you want different behavior for an expected failure mode, express it explicitly using `when` conditions rather than relying on errors.

Note the two distinct timeouts: a *command-level* timeout (the `command.timeout` setting below) is one of the step failures above — it stops the event and records an `error` outcome. The *correlate-level* timeout (the `timeout` setting under [Correlate](#correlate)) is the overall run budget — when it expires the event is recorded with a `timeout` outcome instead. Both fall through to an alert.

The `type` field specifies the type of the command. The following types are supported.

#### query

Executes a query against a queryable system such as Splunk or Logscale.

In the case of an `event transformation`, the query is executed for each event.

In the case of a `stream transformation`, the query is executed ONCE for the entire event stream. Subsequent executions return the same result.

```yaml
command:
    type: query
    source: splunk | logscale | any other registered query command
    query: the query to execute (jinja interpolated)
    time_range: # NOTE: all time ranges are relative (see below)
        before: timespec
        after: timespec
        relative_time_field: any string value # optional
        relative_time_format: any string value # optional
```

Systems register with the hunter in ACE for the `source` field (see [Extending correlation hunts](INTEGRATIONS.md#extending-correlation-hunts)).

In the case of an `event transformation`, the relative `time_range` is relative to the time of the current `event`, which is identified using the `relative_time_field` and `relative_time_format` options. `before` and `after` extend the window around that single event time.

In the case of a `stream transformation`, a relative `time_range` is anchored to the hunt's own query window: `before` extends before the window's start time and `after` extends after its end time. (A stream transform runs once for the whole stream, so there is no single per-event time to anchor to — `relative_time_field`/`relative_time_format` are ignored for stream transforms.)

In either case, if no time range can be determined — an `event transformation` whose `relative_time_field` cannot be resolved, or a hunt run with no query window — the relative `time_range` falls back to being anchored to the hunt's query window (which is the current system time when the hunt is not run over an explicit window).

#### executable

Executes a local binary or script.

In the case of an `event transformation`, the script is called for each event. The optional `stdin` setting controls how the event is fed to the script. If `stdin` is true, then the event is written to stdin as JSONL. If `stdin` is false, stdin is empty (`/dev/null`). In either case, the `args` are jinja interpolated with `_event` (current event) and `_events` (full stream) available.

In the case of a `stream transformation`, the script is called once and passed all events in as JSONL to stdin.

`env` values are interpolated the same way. The script does **not** inherit ACE's environment — see [Credentials in hunts](#credentials-in-hunts).

Every execution runs in a sandbox — see [Executable sandbox](#executable-sandbox). A script that reads a file next to it (a data file, a helper module) must list that file under `files:`.

```yaml
command:
    type: executable
    path: path to the executable on the local file system # can be relative
    stdin: false # optional
    args: # list of arguments to pass to the command line (optional)
      - arg1
      - arg2
    # NOTE arguments are interpolated using jinja with _event and _events
    env:
        SOME_SETTING: "some value"
        LOOKUP_DOMAIN: "{{ _event.domain }}"
    # environment values are also interpolated using jinja with _event and _events
    files: # files the script reads, copied next to it (optional)
      - data/lookup.json # can be relative, like path
```

#### Executable sandbox

A hunt script is written by an analyst or by an AI agent working through the validation API, and a mistake in it must not be able to damage ACE or expose a secret. So every execution runs in a [Landlock](https://docs.kernel.org/userspace-api/landlock.html) sandbox (`saq/collectors/hunter/correlation/sandbox.py`):

- **A private working directory.** Each execution gets a fresh directory under `hunter.correlation.executable.work_dir` (default `DATA_DIR/var/correlation_sandbox`). It is the command's working directory, `HOME` and `TMPDIR`, and it is deleted when the command finishes. It is the only place the command can create, change or delete a file.
- **Staging.** The script (`path`) and every `files:` entry are copied into the working directory, keeping their layout relative to each other, so `Path(__file__).parent / "lookup.json"` still works. The script runs from the copy, so it cannot modify the hunt repository. Sources must be regular files inside a hunt repository: the `git_dir` (or `rule_dir`) of a `hunt_type_*` rule directory, or the directory the validation API unpacks a submitted hunt into. Anything else, including a symlink that points out of the repository, fails the step. A `path` that is already readable in the sandbox runs in place without being copied. Examples are `/usr/bin/jq`, the venv's `python3`, or a bare name such as `echo` that `PATH` resolves to one of those.
- **What it can read.** Only `/usr`, the python runtime (the venv and the interpreter it was built from), `/etc/ssl`, `/etc/ca-certificates`, the few `/etc` files that name resolution, TLS and time zones need, `/dev/null`, `/dev/urandom`, and its working directory. Nothing else is readable. That includes `SAQ_HOME` (config, `.env`, `ssl/`, `signatures/`), the data directory, `/auth`, the SQL volumes, `/home`, `/tmp`, `/proc` and the rest of `/etc`. The list is a constant in `sandbox.py`, not configuration.
- **Limits.** Address space, largest file written, open files and bytes of output read from each of stdout and stderr are set under `hunter.correlation.executable` in `etc/saq.default.yaml`. The CPU-seconds limit is the command's `timeout`. Exceeding a limit fails the step.
- **No leftovers.** The command runs in its own session, and the whole session is killed when the command exits, times out or writes too much output. A process it started in the background does not survive it.
- **Unchanged.** Network access. Every current hunt script needs DNS or HTTPS.

The sandbox needs Linux 5.13 or later with Landlock enabled (the Debian kernel default), plus util-linux `setpriv` and `prlimit`, which are in the ACE image. It needs no capability and no docker compose change. The hunter logs at startup whether Landlock is available. If it is not, every executable command fails as a step error; a command is never run unsandboxed.

#### Credentials in hunts

A hunt has no access to secrets. Hunt templates can read `_event` and `_events` and nothing else: neither the credential store nor ACE's configuration is bound. Hunt validation rejects any template that references `_secrets` or `_config`, and at runtime such a template fails as a step error.

An executable command does not inherit ACE's environment. It gets only a fixed allowlist of variables (`PATH`, `HOME`, locale, `TZ`, `TMPDIR`, `PYTHONUTF8`, the proxy variables and the CA bundle variables; see `EXECUTABLE_ENV_ALLOWLIST` in `saq/collectors/hunter/correlation/commands.py`) plus the values in its own `env:` block. `HOME` and `TMPDIR` are set to the command's private working directory.

A lookup that needs a credential belongs in a [custom command type](#custom-integration-provided-types). A custom command type is Python code in an integration, and it reads its credentials from that integration's configuration.

#### defined

A command can be predefined in the `commands` section. See below on Predefined Commands.

```yaml
command:
    type: defined
    name: name of the command to execute
    arguments: {} # command overrides
```

The `arguments` setting lets you override the default settings in the command. Any fields defined in the `arguments` dict are applied to the `command` block as though they were originally defined that way.

In the example that follows, we defined an external script as "user_lookup" but with an empty argument list. Then in our rule, we correlate to set the field named "user_data" to the value of calling that script, and override the `args` field with the "userId" field in the current data set.

```yaml
commands:
    - name: "user_lookup"
      description: "Example external script"
      type: executable
      path: "scripts/external_lookup.py"
      cache: 1d
      args: []

rule:
    # ... snip ...
    correlate:
        logic:
            - transform:
                type: event
                method: property # store the results in a new property
                property_name: user_data # called "user_data"
                property_type: str # interpret the output as a string
                command:
                    type: defined
                    name: "user_lookup" # <--  reference command by name
                    arguments:
                        args: ["{{ _event.userId }}"] # <-- pass the value of the userId field as the single argument to the command
```

#### custom (integration-provided) types

Any other `type` names a *custom command type* that an integration registers (see
[Extending correlation hunts](INTEGRATIONS.md#extending-correlation-hunts)). A custom type takes
its settings under `options`, not as top-level keys next to `type`:

```yaml
command:
    type: wiz_lookup # the name the integration registered
    timeout: 2m # optional, as for every command
    cache: 1d # optional, as for every command
    options: # whatever the command type accepts
        ip: "{{ _event.src_ip }}"
        include_tags: true
```

- Every string in `options`, including strings nested in lists and dicts, is rendered with
  Jinja before the command runs, with `_event` and `_events` available. A command type gets its
  credentials from its own integration's configuration, so credentials never belong in
  `options`.
- The rendered options are then validated by the command type. A template always renders to a
  string, which the command type converts where it can (`"5"` becomes `5` for a number). A value
  that must be a list or a dict cannot come from a template.
- `options` is not the same thing as a query's `source_options`. `source_options` is passed to
  the query source as written, without rendering.
- `timeout` is handed to the command type, which is responsible for honoring it.
- A command type that cannot be cached rejects `cache`. When a command type can be cached, the
  cache keys on the rendered options together with the event, or the whole stream for a stream
  transform, unless the command type says its result depends only on its options.
- A custom type can be predefined in `commands` and referenced with `defined`. An
  `arguments: {options: {...}}` override replaces the whole `options` dict; it does not merge
  into it.
- The hunt validator (`ace hunt verify`, and the signature validator through
  `POST /api/hunt/validate`) reports two kinds of problem. It reports a type that is not
  registered on the node, including one whose integration failed to load there. It also reports
  options the command type rejects. A template value is only judged after rendering, at run time.
- File paths inside `options` are not resolved relative to the hunt file, and the hunt compiler
  does not package them.
- Correlate-result capture and replay (`--save-correlate-results` / `--correlate-results-file`)
  covers `query` commands only. A custom type always runs live.

### Actions

An `action` defines some kind of an action to take. Actions can interrupt processing (they can stop processing.) Those are denoted here with `(interrupt)`.

All action types support the following optional logging fields:

- `log_level`: the Python logging level for the message (default: INFO)
- `log_message`: a jinja interpolated message to log when the action executes

When an action executes, it emits a log message. If `log_message` is specified, it is rendered via jinja and logged at the specified `log_level`. If neither field is present, a default INFO-level message is logged indicating which action was executed and the result.

Note that an `action` block has both a short and long syntax.

```yaml
# short syntax
action: name

# long syntax
action: 
    type: name # see below
    # additional optional parameters
```

#### action: filter (interrupt)

Discards and stops processing the current event.

```yaml
action:
    type: filter
```

#### action: stop (interrupt)

Stops processing the entire event stream. Any events that ended with an action of alert are still passed on as alerts.

```yaml
action:
    type: stop
```

#### action: discard (interrupt)

Stops processing the entire event stream and discards any alerts already generated.

```yaml
action:
    type: discard
```

#### action: alert (interrupt)

Passes the event as an alert and stops processing the event. Some additional properties of the alert can be modified.

If processing fall through (gets to the end without be explicitly interrupted), then the default action is to alert.

Using this action gives you a way to override certain fields in the alert. This is applied only to the event the action was applied to.

```yaml
action:
    type: alert
    queue: any value # optional
    analysis_mode: any value # optional
```

#### action: log

A no-op action that only triggers logging. Processing continues uninterrupted. Since all actions now log by default, this action type is useful when you want to emit a log message without any other side effect.

```yaml
action:
    type: log
    log_level: INFO # optional
    log_message: jinja interpolated message # optional
```

### Predefined Commands

You can pre-define commands and then reference them by name instead of creating them inline. This allows for some reusability for commonly used commands.

A special top-level YAML key of `commands` is a list of pre-defined commands to make available to all hunts.

```yaml
commands:
    - name: "user_lookup"
      description: "Example external script"
      type: executable
      path: "scripts/external_lookup.py"
      cache: 1d
      args: []
```

These are referenced using the `defined` command type.

### Cache

A command can specify a cache timespec. If defined, results returned are cached in a key/value system where the key is the combined hash of the arguments provided to the command, and the value is the result returned for those arguments. These cached values are kept for the period defined for the timespec, after which they are discarded.

The cached arguments are the *interpolated* ones — for a `query` command, the key is the hash of the Jinja-rendered query text (and its source), not the raw template. So a query that interpolates per-event fields (e.g. `search animal="{{ _event.animal }}"`) caches a separate result per rendered value; each distinct question is cached independently rather than the whole template sharing one entry. (Executable commands likewise key on their rendered `args`/`env`.)

For example, `cache: 1d` will cache results for 1 day.

#### Choosing the timespec

Make sure that you pick the timespec based on how fast the underlying data
changes, not by just copying the neighbouring step.

A couple of key points to consider when deciding what value to use for the timespec:

- **A TTL shorter than the hunt's `frequency` never survives to the next run.** For example, if a hunt has
  `frequency: 00:10:00` and the timespec for a command is `cache: 3m`, the items
  in the cache will expire before the hunt runs again, making the cache useless.
- **This cache is not shared with analysis.** If an ACE analysis module performs
  the same action, it may end up with a different result. ACE analysis modules
  use a separate caching system.

### Timespecs

A timespec specifies some amount of time and uses an abbreviated format of `count[s|m|h|d|w|y]` defined as follows:

- `count`: any integer value
- `s`: seconds
- `m`: minutes
- `h`: hours
- `d`: days
- `w`: weeks
- `y`: years

They can be combined with zero or more whitespace.

Examples:

- `30s`: 30 seconds
- `8h30m30s`: 8 hours 30 minutes 30 seconds
- `8h 30m 30s`: same as above

### Timespec Formats

Some properties require you to define a format used to interpret a time stamp. If the source of the data already has a known timestamp, you don't have to specify it. However, if it does not you may have to specify which field has the timestamp and how to interpret it.

Some predefined interpretations of timestamps are made available.

- `epoch`: normal epoch in seconds
- `epoch_ms`: epoch in milliseconds
- `epoch_ns`: epoch in nanoseconds
- `iso8601`: ISO 8601 format 

### Mapping list fields to observables

A `property` transformation with `property_type: list` stores a list of dicts on the event
(for example, the rows returned by a correlating query). To turn a sub-field of every item in
such a list into observables, use a `*` wildcard segment in an `observable_mapping` entry with
`field_lookup_type: dot`:

```yaml
observable_mapping:
  - fields: ["correlated_logs.*.username"]
    field_lookup_type: dot
    limit: 16
    type: user
```

The `*` iterates every item in `correlated_logs` and plucks `username` from each, creating one
observable per item. List items missing that sub-key are skipped, an empty list yields no
observables, and a missing top-level list key is treated as the field not being present. The
optional `limit` caps how many observables a single entry emits (it also applies to list-valued
fields and Jinja `value` templates that expand to many values). This avoids hand-enumerating
`correlated_logs.0.username`, `correlated_logs.1.username`, ... for each index.

# Implementation Notes

- The new `correlate` functionality runs in between converting an event into a submission.
    - All events are first collected and then passed to `correlate` as the event stream.
- The final event stream that includes all transformations becomes available for observable mapping.
- Query sources (the `source` of a `query` command) and custom command types are both registered from configuration (`hunter.correlation.query_sources` and `hunter.correlation.command_types`), with a python module and class, the same way analysis modules are. See [Extending correlation hunts](INTEGRATIONS.md#extending-correlation-hunts).
- Jinja templates have access to these variables. Event properties are accessed via `_event.property_name` or `_event['key.with.dots']` for keys that contain special characters.

    | Variable | What it is | Where it is bound |
    |---|---|---|
    | `_event` | the current event dict | every template |
    | `_events` | the full event stream list | every template |

    Nothing else is bound: hunts have no access to configuration or secrets (see [Credentials in hunts](#credentials-in-hunts)).
- When merging by time
    - events with identical timestamps are merged in the order of original event stream, then new event stream.
    - the number of events missing timestamps (and thus are not merged) and then a warning is logged with the number of events dropped.
- A stream mutate transformation drops the old stream and uses the new stream instead.
- The current working directory of an executable command is a private directory created for that one execution (see [Executable sandbox](#executable-sandbox)). It is deleted immediately after execution.
- The cache is persistant and global. We'll probably want to use redis for this.
- Since `commands` is a top-level list, common commands can be included with the `include` directive.
- Malformed `correlate` blocks should be treated as a malformed hunt.
- The executed format of all query commands is JSONL. No exceptions.
- The group_by logic applies after correlate has been processed.
- Hunts already have a way to specify a maximun result set size, so this is used to limit per-event query executions.
- When a command errors during a property event transformation, step processing for the affected event stops immediately and the event defaults to alert.