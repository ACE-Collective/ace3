# Hunting

## Overview

A **hunt** represents some kind of a search that executes at some defined frequency. Any results are sent to ACE for analysis. Typically a hunt creates an alert in ACE, however you can configure the hunt to send the data to ACE in a non-alerting mode, allowing ACE to do the extra work to determine if an alert should be generated.

Each hunt is **defined** as a YAML file and stored in a git repository. ACE monitors the `main` branch of each hunt repository and automatically loads any changes detected.

> For the advanced correlation features (the `correlate` rule field and the top-level `commands` key), see [CORRELATION_HUNTS.md](CORRELATION_HUNTS.md). This document covers the base hunt syntax only.

## Hunt Common Syntax

This section defines the syntax that is common to all hunts. Note that the different systems (such as Splunk, Logscale, etc...) might define additional configuration settings documented elsewhere.

> Every hunt goes into its own file. You cannot combine hunts into single files.

> Hunt configuration is validated strictly: every config model forbids unknown keys. A misspelled or unsupported key causes the hunt to fail validation rather than being silently ignored.

```yaml
# OPTIONAL zero or more files to include
# NOTE this directive is a top level directive (like 'rule' is)
# include:
#   - includes/common.yaml

rule:

  # unique identifier for the hunt
  # NOTE this must be unique *globally* across all signature repositories
  uuid:

  # set this to yes to enable this hunt
  enabled: false

  # optional list of instance types this hunt will run on
  # the hunt ONLY runs in the instance types listed here
  # if empty/unset, the hunt does NOT run in any instance
  # possible values are: production, qa, dev
  instance_types:
    - production
    #- dev

  # this ends up being the name of the alert in ACE when the hunt matches something
  # it must be unique
  # NOTE: the name supports event interpolation (Jinja)
  name:

  # optional list of one or more authors of the hunt
  # may be a single string or a list of strings
  author:

  # instructions to the analyst that describes what the hunt is looking for
  # and how to interpret the results
  description:

  # which system to use to execute the hunt: splunk, logscale, or rapid7
  type: splunk

  # custom alert type used to categorize the alert in ACE
  # this is used to decide how the alert is displayed, so this setting matters
  alert_type: hunter - splunk

  # analysis mode for the alert (defaults to correlation if not specified)
  #analysis_mode: correlation

  # how often to execute the hunt in HH:MM:SS format
  frequency: "01:00:00"
  # alternatively, you can use cron schedule syntax instead of frequency
  #frequency: "0 * * * *"

  # list of tags to add to the root object of the analysis
  # supports event interpolation (Jinja)
  tags: []

  # optional playbook URL for this hunt
  # supports event interpolation (Jinja)
  #playbook_url: https://wiki.example.com/playbooks/hunt_name

  # optional queue to submit alerts to (defaults to the default queue)
  #queue: default

  # optional suppression time in HH:MM:SS format to suppress alerts after one fires
  #suppression: "24:00:00"

  # how far back to run the hunt from the last time the hunt ran (or the current time if the hunt has never run)
  # typically this is the same as the frequency, but can be longer if the search you're building requires it
  # for example, if your search is based on statistics over the past 24 hours, you would set this to 24:00:00
  # even if the frequency is set to every hour
  time_range: "01:00:00"

  # the maximum time range that can be used for a single execution as the hunt attempts to catch up
  max_time_range: "24:00:00"

  # optional offset to run the hunt at (shifts the entire time window earlier)
  # useful for log sources that are known to be delayed
  #offset: "00:05:00"

  # set this to yes to ensure that all time is covered
  # when full coverage is set to yes, the starting time of the next hunt will be the ending time of the last execution
  full_coverage: true

  # optional interpolation template (Jinja) for deduplication
  # when set, submissions get a key enabling the ability to suppress duplicates
  # this is useful when external log sources replay or re-index events
  # (e.g., Microsoft sign-in logs reappearing in Splunk)
  #dedup_key:

  # group_by is used to group events into alerts
  # and is then appended to the description of each alert
  # if not set, each result is treated as a separate alert
  # use the special value "ALL" to group all results into a single alert
  #group_by:

  # description_field specifies which event field to use for the alert description suffix
  # if not set, the group_by field value is used for the description (default behavior)
  # this allows decoupling the grouping key from the alert description
  #description_field:

  #
  # optional user and app context to use for the hunt (Splunk only)
  # if not set, the default user and app context will be used
  #splunk_user_context:
  #splunk_app_context:

  #
  # you can specify the contents of the actual query to perform in one of two ways:
  # 1. a path to a file that contains the query (relative paths are relative to SAQ_HOME) using the search key
  # 2. the query itself as a string using the query key
  #

  # path (relative paths are relative to SAQ_HOME) to the file that contains the actual query to perform
  # this is useful if the query is extremely large
  #search: hunts/sample/sample.sql

  # the query to perform, inline
  # NOTE that this is a YAML file so you need to follow the YAML syntax rules
  # multiple lines can be represented using the literal block scalar (|) or folded block scalar (>)
  query:

  # most splunk queries will use this setting
  # when set, the index time is used to determine the time range of the query, rather than the actual event time
  # this ensures all events are eventually included in the search
  # if your query is based on statistics that require the event time, set this to no
  use_index_time: true

  # maximum number of results to return from the query
  # if not set, uses the configured default from the query_hunter configuration section
  #max_result_count: 1000

  # timeout for the query (in HH:MM:SS format)
  # if not set, uses the configured default from the query_hunter configuration section
  #query_timeout: "00:05:00"

  # optional icon configuration to use for alerts
  # can either be a "blueprint_file_location" or a "url"
  # see alert icons documentation for more details
  #icon_configuration:
    #blueprint_file_location:
      #name: static
      #path: images/alert_icons/splunk.png
    #url: https://www.splunk.com/favicon.ico

  # optional alert template to use to display the alert in ACE
  alert_template: analysis/custom/hunter_splunk.html

  #
  # map fields to observables in ACE
  #
  # format:
  # - fields: [<field_name_1>, <field_name_2>, ...] (must specify at least one field)
  #   field_lookup_type: <key|dot> (optional, defaults to key)
  #   value: "<OPTIONAL value to use for the observable>" (optional; if not specified, the value of the first field is used)
  #   type: <observable_type> (required)
  #   time: <true|false> (optional, defaults to false)
  #   limit: <int> (optional; caps how many observables this entry emits from a list field / wildcard / value template)
  #   directives: [<directive_1>, <directive_2>, ...] (optional)
  #   tags: [<tag_1>, <tag_2>, ...] (optional)
  #
  observable_mapping: []

    #
    # examples:
    #

    #- fields: [cmdline]
      #type: command_line
      #time: false
      #directives: []
      #tags: []

    #- fields: [device.hostname, file_path]
      #type: file_location
      #value: "{{ device.hostname }}@{{ file_path }}"
      #time: false
      #directives: [collect_file]
      #tags: ["collected_from:{{ device.hostname }}"]
```

## Top Level Keys

There are two top level keys in a hunt. The `rule` key is required and contains the configuration for the hunt. The `include` key is optional and defines additional YAML files that should be included as part of this hunt.

The top-level `commands` key (optional) is also available for advanced correlated hunting — see [CORRELATION_HUNTS.md](CORRELATION_HUNTS.md).

### `include` (list of strings)

A hunt can define another YAML file to include by using the `include` top level key. This contains a list of files to include. Relative paths are relative to the location of the file that included them.

This allows us to define common settings. For example, a given log source in Splunk is always going to have certain fields. So we can define how those fields are mapped once, and then include that mapping in each hunt that uses them.

> The `include` directive will load **any** file path you give it. Separately, files whose names end with `.include.yaml` are **skipped** by the hunt loader as standalone hunt entrypoints (so a shared include file is not mistakenly run as its own hunt). The two behaviors are independent: you do not have to name an included file `.include.yaml` for it to be includeable, but naming it that way keeps it from being treated as a hunt on its own.

### `rule` (dict)

The `rule` top level key is a dictionary that contains the configuration of the hunt.

## Common Settings

You will see these in just about every hunt configuration.

### `uuid` (string)

The unique identifier for the hunt. We use UUIDv4 for these. These **must** be unique. You can use any tool you want to generate these.

### `enabled` (boolean)

You can turn a hunt off without deleting it by setting this to disabled. This is a great way to keep hunts around for historical reference without having them running.

### `name` (string)

The unique name for the hunt. This value is used when referencing the hunt, and ACE often appends the uuid to the name when displaying it.

The `name` supports event interpolation (Jinja). See [Field Value Interpolation](#field-value-interpolation).

### `description` (string)

Contains the detailed explanation of what this hunt is looking for, and/or why it is looking for it. This gets added to the alert so that the analyst understands why he or she is looking at the alert.

> This is one of the most important fields in the hunt as it describes the **why** behind the creation of the hunt. Add as much detail as *you* would want if you were receiving this alert to analyze!

> The `description` value is **not** interpolated. (Among the alert title/description inputs, only `name` is rendered through the template engine.) When `description_field` or `group_by` is set, the relevant field value is appended to the description — see those settings.

### `instance_types` (list of strings)

This controls which instance of ACE this hunt runs in. Valid values are `production`, `qa`, and `dev`. You must list which ones you want the hunt to run in. Matching is case-insensitive.

A typical workflow might include running an experimental hunt in the development instance first, then moving to production after.

> The hunt only runs in the instances specified. **If you do not specify any instance (empty or omitted), the hunt will not run at all.**

### `type` (string)

Defines which system to use when executing this hunt. The following values are currently supported.

- `splunk`
- `logscale`
- `rapid7`

Each type is registered by a `hunt_type_<name>` configuration section naming the Python class that
executes it, the `rule_dirs` its hunts are loaded from, and a `schedulable` flag.

**A hunt type may be configured as non-schedulable** (`schedulable: false`), in which case it has no
`rule_dirs` and ACE never loads a hunt of that type from disk. Hunts of that type can still be
submitted through the hunt validation API and executed on demand — validation and ad-hoc querying
are the entire surface. This exists for backends whose query cost is governed by a quota that has to
stay under human control, where a fleet of scheduled hunts could exhaust the budget that the rest of
the system depends on. Writing such a hunt into a rules directory has no effect, so check the type's
configuration before authoring one.

### `alert_type` (string)

This is used to categorize alerts created by this hunt. The primary use of this field is for metrics. However, ACE can (optionally) use this to select an icon to display alongside the alert if one isn't specified in the hunt.

We tend to follow a naming scheme here for this value: `hunter - type - logsource - detailed`

- hunter (constant value for all hunts)
- type (same as **type** defined above, which system is used)
- logsource (which logsource(s) this hunt uses)
- detailed (optional additional categorization fields)

Consider the following example we might use if creating a hunt that detects phishing using the phishfinder log source:

```
hunter - splunk - phishfinder
```

Consider this example that is pulling alert data from the crowdstrike log source.

```
hunter - splunk - crowdstrike - alerts
```

### `description_field` (string, optional)

The name of the field to use to append a string to the end of the ACE alert's title/description. If this is not specified but the `group_by` field is, then the `group_by` will be appended to the alert's description to maintain ACE's original behavior.

### `group_by` (string, optional)

The name of the field to use to group events into alerts.

By default every result returned by the execution of hunt (each row) results in a new ACE alert. This setting allows you to group events by some field, and then submit each grouping as an alert.

For example, an IDS-type alert might include the name of the signature that fired and the source and destination IP address. If the same signature fires for 100 different source IP addresses, by default 100 different alerts would be created. But if you set the `group_by` to be the name of the field that contains the name of the signature, then only a single alert would get created with all 100 events attached to it (probably more what you want.)

Use the special value `ALL` to group all results into a single alert.

> If `group_by` is specified and `description_field` is not specified, then the `group_by` value will be appended to the ACE alert's description. The `description_field` allows you to override this and decouple the alert description from the alert grouping.

> If `group_by` is specified and the field does not exist in the events, each event becomes a separate alert as if there were no `group_by` at all.

### `dedup_key` (string, optional)

The interpolation string to use to build the unique key to use to deduplicate ACE alerts. For example, with our discovery of duplicate Microsoft sign-in alerts where the logs seemed to be getting re-sent to Splunk up to a week later, this key can be set to prevent ACE from creating another alert.

It uses the same Jinja interpolation as `observable_mapping` does (see [Field Value Interpolation](#field-value-interpolation)):

```yaml
# Use the value of a single field:
dedup_key: "{{ correlationId }}"

# Use the value of multiple fields as a composite key:
dedup_key: "{{ user }}-{{ src_ip }}-{{ action }}"
```

> If the `dedup_key` is set, ACE will automatically prefix it with the UUID of the hunt so that multiple hunts do not interfere with each other.

> If the `group_by` field is also set for the hunt, the computed `dedup_key` is built from the *first event* in the group.

### `query` (string)

The hunt to execute.

The contents of this depend on the type of the hunt. For example, for a Splunk hunt, this would contain the Splunk query to execute.

You can specify the query in one of two ways:

- `query`: the query itself, inline, as a string. For large queries it is useful to leverage YAML syntax for multi-line strings.
- `search`: a path to a file that contains the query (relative paths are relative to `SAQ_HOME`). Useful when the query is extremely large.

### `frequency` (string) [HH:MM:SS]

Defines how often to execute the hunt in the format of "HH:MM:SS" where HH is hours, MM is minutes and SS is seconds. ACE does its best to execute the hunt at the frequency specified.

You may alternatively specify a cron schedule (e.g. `frequency: "0 * * * *"`) instead of an HH:MM:SS duration.

> There are times where this does not happen. ACE has features to work around this.

## Time Range Settings

These settings work with the `frequency` setting to control the time range used when the hunt is executed.

### `use_index_time` (boolean)

When this is set to true, ACE will use the "index" (sometimes called "ingestion") time of events rather than the event time. This is usually what you want as it allows ACE to ensure that all data is searched. When in doubt, set this to true.

### `full_coverage` (boolean)

When this is set to true, ACE will automatically set the time_range equal to the end of the previous execution, so that all events are covered. Otherwise, ACE simply uses the time_range, regardless of the last execution time. When in doubt, set this to true.

### `time_range` (string) [[DD:]HH:MM:SS]

Defines how far back to search for data. This may or may not be used, see the section below called [Time Ranges](#time-ranges). When in doubt, set it equal to the `frequency`.

### `max_time_range` (string) [HH:MM:SS]

Defines the maximum time range allowed for a single execution of the hunt. This allows you to control the impact "catching up" has on the system if ACE falls behind. When in doubt, set it to `24:00:00`.

### `offset` (string, optional) [HH:MM:SS]

Defines an offset to apply (in HH:MM:SS format) to the computed time range. The offset shifts the **entire window** (both its start and end) earlier by the given amount, allowing you to adjust the rolling window of events that are searched. This is useful for log sources that fall behind when full_coverage is set to false. By default no offset is applied.

### `suppression` (string, optional) [HH:MM:SS]

If set, triggers a suppression of future alerts for this hunt every time an alert is generated for this hunt. If you have a case where a hunt doesn't trigger often, but when it does it triggers a lot, you can use this feature to prevent ACE from generating new alerts for a given amount of time for a specific hunt.

This setting is rarely used.

### `query_timeout` (string, optional) [HH:MM:SS]

Sets a query timeout for this hunt. If the hunt does not complete within the given amount of time, it is considered failed and ACE tries again later.

This setting is rarely needed.

## Other Settings

### `tags` (list of strings, optional, interpolated)

Optional setting that adds the given tags directly to the alert. Each string becomes a tag. Supports [Field Value Interpolation](#field-value-interpolation).

### `queue` (string, optional)

Controls which ACE queue alerts are assigned to. If not set then the default queue is used. This allows hunts to target specific queues (which are just a way for alerts to be organized in ACE.)

### `max_result_count` (integer)

Controls the maximum number of events returned by a hunt. The default varies by system.

### `playbook_url` (string, optional, interpolated)

An optional URL that should reference a playbook to consider when reviewing the alert. Supports [Field Value Interpolation](#field-value-interpolation).

### `pivot_links` (list of dicts, optional)

An optional list of pivot links which get added to the alert as a way to allow the analyst to quickly pivot over to some other tool. Pivot links always open in new windows in the browser. A pivot link has the following fields.

- `url` (string, interpolated): The URL to use for the link.
- `text` (string, interpolated): The text to use for the link.
- `icon` (string, optional): The icon to use for the link.
- `target` (string, optional): Where the link is attached — `root` (default) or `analysis`.
- `limit` (integer, optional): Caps how many pivot links a single entry emits when its interpolation expands to many values.
- `overflow` (optional): Controls behavior when the number of generated links exceeds `limit`.

Examples of supported `icon` values:

```yaml
# direct URL to image
icon: "https://www.splunk.com/favicon.ico"

# base-64 data URL
icon: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="

# relative to the app/static/ directory
icon: "images/alert_icons/splunk.png"
```

### `summary_details` (list of dicts, optional, interpolated)

An optional list of summary details to add to the alert. This is useful for pulling out key pieces of information that you'll want displayed every time. Each summary is added as a separate section near the top of the alert.

A summary detail has the following fields:

- `content` (string, interpolated): The content to add to the alert. This is interpolated with event data.
- `header` (string, optional, interpolated): An optional header to add to the content, displayed as a section header.
- `format` (string, optional): The format of the content value. The default is `md`.
- `limit` (integer, optional): The maximum number of summaries that will be added. The default is 100.
- `grouped` (boolean, optional): If true, the interpolation of all events is combined into a single summary (useful for creating lists). By default each event in the hunt result generates its own summary detail.
- `dedup_fields` (list of strings, optional): Fields used to deduplicate summaries so the same content is not added repeatedly.
- `required_fields` (list of strings, optional): Fields that must be present **and non-empty** in the event for the summary to be generated.

> If a summary detail specifies an event field for interpolation and that event field does not exist in the event, then that summary detail is skipped for that event.

The `format` field supports the following values:

| Format | Description | Notes |
|--------|-------------|-------|
| `txt` | Plain text. | Content is displayed as normal text. |
| `pre` | Preformatted text. | Content is displayed as fixed text. |
| `md` | Markdown. | Content is rendered as HTML from Markdown. Content is rendered for each event. |
| `jinja` | | Content is rendered once for the entire event stream, and your jinja is expected to loop over each event. |

### `query_prefix` / `query_suffix` (string, optional)

Optional strings prepended (`query_prefix`) and appended (`query_suffix`) to the resolved query before execution.

### `auto_append` (string, optional)

A string appended to the query after the time spec is applied. For Splunk hunts this defaults to `| fields *`.

### `ignored_values` (list, optional)

A hunt-level list of regex patterns (matched with `re.fullmatch()`) used to ignore values across the hunt's observable mappings. This is distinct from the per-mapping `ignored_values` documented under [Observable Mapping](#observable-mapping).

## Advanced Settings

These settings are for people who have been using ACE for a while and understand the basics of how it works.

### `analysis_mode` (string, optional)

Submissions to ACE become alerts by setting the analysis mode to correlation. This is the default for hunts. You can override this here by using a different analysis mode. If you override this, then the submission does not automatically become an alert.

> The submission can still become an alert if ACE discovers a detection point while analyzing the results.

### `alert_template` (string, optional)

This advanced setting is used to control which ACE template the hunt should use. This is subject to change in future versions.

### `icon_configuration` (dict, optional)

This special directive allows the author to define a custom icon to use when ACE displays the alert in the alert management view. There are two different ways to select an icon, you must use one or the other (or neither for the default ACE icon.)

**Flask Blueprint Reference** — the way to reference the static content contained in a Flask blueprint.

```yaml
icon_configuration:
  blueprint_file_location:
    name: static
    path: images/alert_icons/splunk.png
```

**Image URL** — the way to reference a normal image URL. Note that you can use data URLs here, so you can embed the image in the YAML as base64 encoded data.

```yaml
icon_configuration:
  url: https://www.splunk.com/favicon.ico
```

### Splunk-specific settings

These apply when `type: splunk`.

- `splunk_config` (string, optional): Which configured Splunk server to use. Defaults to `default`.
- `splunk_user_context` (string, optional): The Splunk user namespace to run the query in. If not set, the default context is used.
- `splunk_app_context` (string, optional): The Splunk app namespace to run the query in. If not set, the default context is used.

You can also include another file's contents directly inside a Splunk query string using a `<include:PATH>` token. This is a query-text include and is distinct from the top-level `include:` directive.

### Correlated hunting (`correlate`, `commands`)

The `rule` key supports an optional `correlate` block, and the document supports an optional top-level `commands` key, that together provide advanced correlation capabilities (gathering more data into hunt results and branching on it). This is documented separately in [CORRELATION_HUNTS.md](CORRELATION_HUNTS.md).

## Time Ranges

> This only applies to hunts for query-based systems, such as Splunk and Logscale.

The `frequency` setting defines how often a hunt should run. This is true no matter what. The time range that is used by ACE when executing the hunt depends on some of the other settings.

First, if `use_index_time` is true, then ACE will use the "index" time (sometimes called the ingestion time.) If `use_index_time` is false, ACE will use the "event" time.

If `full_coverage` is true, ACE will attempt to ensure that all time is fully covered by the execution of the hunt. This means that the time range will start at the end of the time range of the last time the hunt was executed.

If `full_coverage` is false, ACE will use the time_range relative to the current time.

If `full_coverage` is true and the hunt has never executed before, then the time_range is also used in this case, but only the first time.

If `full_coverage` is true and ACE has been unable to execute the hunt on the scheduled frequency (it has fallen behind), ACE will attempt to catch up by using a larger time range than what the frequency would typically call for. However, it will never exceed, for a single call, the value set for `max_time_range`. This gives us a way to allow expensive (slow) searches to catch up without having a negative impact on the system.

> Never set `max_time_range` equal to or lower than time_range! When in doubt, use `24:00:00`.

If `offset` is set to a value, then the entire computed time range is shifted earlier by the given amount.

### Guidelines for `use_index_time`, `full_coverage` and `offset`

Usually a hunt is just performing some kind of a search, and you usually want to make sure that all of the data is searched. In that case, you want `use_index_time` and `full_coverage` set to true. This is the most common configuration.

If your hunt does some kind of a computation or uses some kind of logic that is based on event time, then `use_index_time` and `full_coverage` should be set to false. A good example of this would be something that computes a number of failed logins over a certain period.

If `use_index_time` is set to false and the log data that you are searching is often behind, you can use offset to search by an `offset`. For example, if you find that a log source is usually 15 minutes behind, you can use a 20 minute offset to help ensure you can scan all of the data.

### Guidelines for `frequency`, `time_range` and `max_time_range`

Most query systems are very efficient with queries that execute over a small time range. The smaller the frequency, the faster the alert can get into ACE. However, you do need to make sure you don't overload the search capabilities of the system.

Here's a general rule of thumb to follow, feel free to research and experiment.

When we say "hunt compute impact" we mean the impact of the search on the system. For example, looking for a simple string would be light, but looking for a complex regular expression might have a high impact. You need to test your hunt to determine how "fast" or "slow" it is, and then set your frequency accordingly.

| Hunt Compute Impact | frequency | max_time_range |
|---------------------|-----------|----------------|
| light | 00:01:00 to 00:05:00 | 24:00:00 |
| moderate | 00:15:00 | 24:00:00 |
| high | 01:00:00 | 08:00:00 |

### Multiple Time Ranges

For Splunk hunts that use subsearches as part of the query, ACE has the ability to set the time range on both the outer and inner searches. This is important because without an explicit time range set within the subsearch, it will use the time range set by the "date picker" – which ACE always sets to a 60 day window. This is often going to be too large of a window for a Splunk subsearch due to limits Splunk imposes on them (60s max runtime and 50,000 total results).

The solution to this is to use the `time_ranges` field in the hunt's config.

> The `time_ranges` field takes priority over the `time_range` field.

The `time_ranges` field accepts either a plain duration string (for lookback only) or a dict with `duration_before` and `duration_after`:

```yaml
# Shorthand — lookback only (duration_after defaults to 0):
time_ranges:
  TIMESPEC: "00:30:00"

# Full form — explicit before and after:
time_ranges:
  TIMESPEC:
    duration_before: "01:00:00"
    duration_after: "24:00:00"
```

You then control where ACE injects these time ranges by placing matching tokens in your query. A token has the form `<NAME>` and must have a corresponding key in `time_ranges`.

> Every `<...>` token used in the query must have a matching key in the `time_ranges` map. When `time_range` is not set, a key named `TIMESPEC` is required. By convention the token/key names begin with `TIMESPEC` (e.g. `TIMESPEC_OUTER`, `TIMESPEC_INNER`).

```yaml
rule:
  name: Suspicious login with wider correlation
  frequency: "00:10:00"
  time_ranges:
    TIMESPEC_OUTER: "00:10:00"
    TIMESPEC_INNER: "00:30:00"

  query: |
    <TIMESPEC_OUTER>
    index=auth sourcetype=login action=success
    | search
        [search <TIMESPEC_INNER>
          index=threat_intel sourcetype=ip_blocklist
          | fields src_ip
        ]
```

## Observable Mapping

You can map fields to observables in ACE. This allows ACE to execute additional automation based on the results of the hunt.

Each element of the `observable_mapping` setting is a dictionary with the following fields defined.

### `fields` (list of strings)

Defines which fields must be present for the observable to get created. Note that multiple fields can be specified.

A single field may also be specified using the singular `field` (string) key, which is treated as a one-element `fields` list.

> Some observables in ACE are complex types, containing multiple values that are encoded in weird ways.

### `fields_mode` (all/any)

Because `fields` is a list of strings and can contain multiple strings, `fields_mode` can be used to affect how ACE treats multiple fields. By default (or if omitted), `fields_mode` is set to `all`. This is best illustrated with a basic example:

This config would create a SINGLE observable only if the log/event has the `user` AND `username` fields. The value of the observable comes from the first field listed, so the `user` field in this case.

```yaml
observable_mapping:
  - fields: [user, username]
    fields_mode: "all"  # default
    type: user
```

This config would create up to TWO observables, one using the value of the `user` field (if it exists) and one using the value of the `username` field (if it exists):

```yaml
observable_mapping:
  - fields: [user, username]
    fields_mode: "any"
    type: user
```

### `field_lookup_type` (key/dot)

Controls how each entry in `fields` is resolved against the event. Defaults to `key`.

| Type | Description |
|------|-------------|
| `key` | The field name is used as a key to look up the value directly in the event data (e.g. `field_name` → `event["field_name"]`). |
| `dot` | The field is treated as a dotted path to access nested values in the event data using the [glom](https://glom.readthedocs.io/) python library (e.g. `device.hostname` → `event["device"]["hostname"]`). |

With `field_lookup_type: dot`, a `*` segment in the path iterates every item of a list field and plucks the remaining sub-key from each (e.g. `correlated_logs.*.username`). List items missing that sub-key are skipped, an empty list yields no observables, and a missing top-level list key is treated as the field not being present.

### `type` (string)

Defines the type of observable to add to ACE.

The type can use Jinja interpolation to dynamically set the type based on data from the events. For example: `{{ cloudPlatform }}_user_id`. However, if the type this ends up resolving to is not defined in `observable_types.yaml`, the observable will fail to be added. See the `fallback_type` key for more information.

> All of the observable types that ACE knows about/supports are defined in `observable_types.yaml`.

> ACE has special support for file content. See the section on [Event Fields as File Content](#event-fields-as-file-content).

### `fallback_type` (string)

If the observable mapping uses an interpolated `type`, and the type it ends up resolving to is not defined in the `observable_types.yaml` file, then a fallback type may be defined so that the observable will still be added with a more generic type.

Using the `{{ cloudPlatform }}_user_id` example, if that resolved to `aws_user_id`, but `aws_user_id` is not defined in `observable_types.yaml`, then you might consider setting `fallback_type` to something like `cloud_user_id`.

The `fallback_type` itself must be defined in `observable_types.yaml`.

### `display_type` (string, optional)

This optional setting allows you to add a custom alias for a given observable's type. This allows you to differentiate between multiple instances of the same thing.

For example, you might have two ip type observables, but one is a source ip and the other is a destination ip. You can use this setting to add that context.

This gets displayed in ACE as **display_type (actual_type)**.

### `display_value` (string, optional, interpolated)

An optional alias for the displayed value of the observable (the underlying observable value is unchanged).

### `value` (string, optional, interpolated)

By default, the value of the observable is set to the value of the field converted into a string.

This optional setting allows you to override the value and set it to something else. See the section on [Field Value Interpolation](#field-value-interpolation) to understand how this could be used.

### `ignored_values` (list, optional)

A list of regex patterns to ignore when mapping the observable. Patterns are matched with `re.fullmatch()`.

### `limit` (integer, optional)

Caps how many observables a single mapping entry emits when a list-valued field, a `*` wildcard path, or a Jinja `value` template expands to many values.

### `time` (boolean, optional)

If set to true, this causes ACE to assign a time to the observable. The time is equal to the "event time" of the event (according to the system the hunt searches.)

This is important for certain types of analysis that need a more specific time frame (around the event) instead of the time the alert was generated, which is often some time after the time the event occurred.

> Don't go overboard with setting time to true. Only use it when it makes sense. A single instance of an observable with a given type and value can be referenced multiple times by different analysis modules. However, assigning a time makes each reference unique. This causes the analysis tree to grow as ACE treats each observable uniquely (and fully analyzes each one!)

### `tags` (list of strings, interpolated)

An optional list of tags to add to the observable.

### `directives` (list of strings, interpolated)

An optional list of directives to add to the observable.

### `volatile` (boolean, optional)

Observables are by default **not** considered *volatile*.

An observable should be set to volatile if you're adding it for the purposes of **detection**. It should *not* be set if you're adding the observable for the purposes of **alert enrichment**. The analysis of an observable with volatile set to true is not displayed in the ACE gui without selecting the Show All Observables button.

### `file_name` (string, interpolated)

This is required if the `type` is set to `file`. This controls the name of the file used to store the contents of the data. See the section [Event Fields as File Content](#event-fields-as-file-content).

### `file_decoder` (string, optional)

This is optional if the type is set to file. This controls how the contents of the field are decoded into bytes to be written to file. The following decoders are available to be used.

If no decoder is specified then the contents of the field are written as utf-8 encoded string data.

| value | description |
|-------|-------------|
| `base64` | Base64 encoded data |
| `ascii_hex` | Hex encoded data |

### `relationships` (list of dicts, interpolated, optional)

An optional list of relationships between this observable and another. There are a few specific use cases for this, where an analysis module in ACE might require there to be a relationship. The value is a list of dicts with the following schema.

```yaml
type: RELATIONSHIP_TYPE
target:
  type: OBSERVABLE_TYPE
  value: OBSERVABLE_VALUE  # interpolated
```

The `RELATIONSHIP_TYPE` is a string from the following list (subject to change):

```
related_to
downloaded_from
executed_on
extracted_from
is_hash_of
logged_into
redirected_from
```

The `OBSERVABLE_TYPE` and `OBSERVABLE_VALUE` specify which *other* observable this observable is related to. Note that `OBSERVABLE_VALUE` can be interpolated with event data.

> If there are multiple observables with the same type and value (as is the case when observables have an associated time property), **then the first observable is selected**.

## Event Fields as File Content

Some log sources include file content (or snippets of file content) as encoded data in search results. ACE can treat the contents of these fields as file data and analyze accordingly.

When mapping an observable this way, set the `type` to `file` and then set the `file_name` and `file_decoder` values appropriately. ACE will then create files, decode the value and save the contents to the files, then analyze the files.

## Field Value Interpolation

Certain settings can have their final values computed based on interpolated event data. This allows you to include (or format) parts of the data present in the search results into specific fields.

The settings that support interpolation are listed in this documentation as "interpolated".

### Syntax

Interpolation uses **Jinja2**. You reference an event field with `{{ field_name }}`. You can have multiple interpolations in a single string.

Events are pre-flattened before rendering, so log sources that emit flat dotted keys (e.g. a field literally named `"device.hostname"`) are addressable with natural Jinja accessor syntax: `{{ device.hostname }}`. Splunk multi-value field markers (a trailing `{}` on a key segment) are stripped during this flatten step.

Because the engine is Jinja2, you have the full Jinja expression and filter language available (conditionals, filters, etc.), not just simple field substitution.

### Examples

```
{{ field_name }}        -> the value of event field "field_name"
{{ device.hostname }}   -> the value of nested field event["device"]["hostname"]
                           (or a flat key literally named "device.hostname")
{{ device.hostname }}@{{ file_path }}
                        -> event["device"]["hostname"] + "@" + event["file_path"]
```

> The `key` vs `dot` distinction (looking a field up by exact key versus traversing a dotted path) applies to the `field_lookup_type` setting used by `fields` in [Observable Mapping](#observable-mapping) — it is not part of the interpolation syntax. In interpolated strings, use Jinja `{{ ... }}` directly.
