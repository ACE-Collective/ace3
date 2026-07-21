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
    timeout: 30s # optional (default 30s)
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

Systems register with the hunter in ACE for the `source` field.

In the case of an `event transformation`, the relative `time_range` is relative to the time of the current `event`, which is identified using the `relative_time_field` and `relative_time_format` options. `before` and `after` extend the window around that single event time.

In the case of a `stream transformation`, a relative `time_range` is anchored to the hunt's own query window: `before` extends before the window's start time and `after` extends after its end time. (A stream transform runs once for the whole stream, so there is no single per-event time to anchor to — `relative_time_field`/`relative_time_format` are ignored for stream transforms.)

In either case, if no time range can be determined — an `event transformation` whose `relative_time_field` cannot be resolved, or a hunt run with no query window — the relative `time_range` falls back to being anchored to the hunt's query window (which is the current system time when the hunt is not run over an explicit window).

#### executable

Executes a local binary or script.

In the case of an `event transformation`, the script is called for each event. The optional `stdin` setting controls how the event is fed to the script. If `stdin` is true, then the event is written to stdin as JSONL. If `stdin` is false, it is not. In either case, the `args` are jinja interpolated with `_event` (current event) and `_events` (full stream) available.

In the case of a `stream transformation`, the script is called once and passed all events in as JSONL to stdin.

```yaml
command:
    type: executable
    path: path to the executable on the local file system # can be relative
    stdin: false # optional
    args: # list of arguments to pass to the command line (optional)
      - arg1
      - arg2
    # NOTE arguments are interpolated using jinja
    env:
        key_1: value
        key_2: value
    # environment values are also interpolated using jinja
```

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
      env: {}
```

These are referenced using the `defined` command type.

### Cache

A command can specify a cache timespec. If defined, results returned are cached in a key/value system where the key is the combined hash of the arguments provided to the command, and the value is the result returned for those arguments. These cached values are kept for the period defined for the timespec, after which they are discarded.

The cached arguments are the *interpolated* ones — for a `query` command, the key is the hash of the Jinja-rendered query text (and its source), not the raw template. So a query that interpolates per-event fields (e.g. `search animal="{{ _event.animal }}"`) caches a separate result per rendered value; each distinct question is cached independently rather than the whole template sharing one entry. (Executable commands likewise key on their rendered `args`/`env`.)

For example, `cache: 1d` will cache results for 1 day.

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
- The process of "registering query commands" should work in a similar way that analysis modules are registered.
    - There should be an internal API for registering query commands with the hunting system.
    - There should be a way to define, through configuration, a python module and class to register.
- All jinja templates have access to two variables: `_event` (the current event dict) and `_events` (the full event stream list). Event properties are accessed via `_event.property_name` or `_event['key.with.dots']` for keys that contain special characters.
- When merging by time
    - events with identical timestamps are merged in the order of original event stream, then new event stream.
    - the number of events missing timestamps (and thus are not merged) and then a warning is logged with the number of events dropped.
- A stream mutate transformation drops the old stream and uses the new stream instead.
- The current working directory of a command is a temporary directory created for the execution of the hunt. It is deleted immediately after execution.
- The cache is persistant and global. We'll probably want to use redis for this.
- Since `commands` is a top-level list, common commands can be included with the `include` directive.
- Malformed `correlate` blocks should be treated as a malformed hunt.
- The executed format of all query commands is JSONL. No exceptions.
- The group_by logic applies after correlate has been processed.
- Hunts already have a way to specify a maximun result set size, so this is used to limit per-event query executions.
- When a command errors during a property event transformation, step processing for the affected event stops immediately and the event defaults to alert.