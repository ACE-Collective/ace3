# Alert automation

ACE can act on an alert by itself when a configured condition holds. The first case it handles: an
external remediation probe (`saq/remediation/external/`) confirms that an email security product
removed an email an open alert is about. ACE then sets the alert's disposition to DELIVERY and
queues its own removal of every delivery of that message. ACE's removal is a backstop in case the
product reports a removal it did not actually make.

The feature is a small framework of **rules**. Each rule has one **trigger**, which finds the
alerts the rule applies to, and a list of **actions**, which run on each of those alerts. Core
ships one trigger and three actions, and an integration can register more of each. The code is in
`saq/alert_automation/`.

## Rules

A rule is an `alert_automation_rule_<name>` block, scanned by prefix like
`external_remediation_probe_<name>`:

```yaml
alert_automation_rule_confirmed_removal:
  name: confirmed_removal
  enabled: true
  mode: dry_run                  # dry_run | enforce
  trigger:
    type: external_remediation_confirmed
    probe: some_probe            # an external_remediation_probe_* name
    max_age_hours: 120
  actions:
    - type: disposition
      disposition: DELIVERY
      comment: "{probe} confirmed removal of {observable} at {event_time}; ACE removal queued as a backstop"
    - type: remediate
      targets: same_message
```

A rule is disabled and in `dry_run` mode unless it says otherwise. Its `name` is recorded with
every run, so renaming a rule makes it act again on the alerts it already acted on.

The rule block rejects unknown keys when the configuration loads, in every process. The trigger
and action blocks are validated against their type's `config_class` when the service loads the
rule, so no other process imports the classes just to read the configuration. Those blocks reject
unknown keys too. A rule that fails to load is logged at ERROR with its name in `extra`, and the
other rules still run.

Comments are templates. A comment may name the fields the rule's trigger provides, plus `{rule}`
and `{alert_uuid}`. A template that names any other field fails the rule when it loads.

## Triggers

A trigger returns candidate alert uuids, each with its **evidence**: what the run records and the
actions are given. It also re-checks that its condition still holds for a set of alerts. The
disposition action passes that re-check to `set_dispositions(eligible=...)`, which runs it under
the alerts' row locks.

### `external_remediation_confirmed`

Matches an alert that has an `external_remediation_check` row with `probe_name` equal to `probe`
and `result = CONFIRMED`, updated within `max_age_hours` (default 120). The age is compared
against the database's `NOW()`. One confirmed delivery is enough. The probe must be configured,
and the trigger names no vendor.

A check row whose `alert_uuid` has no `alerts` row matches nothing. The probe's analysis module
often confirms before the alert row exists, and the rule acts on a later sweep once it does.

The evidence is the confirmed check rows: `{"probe": ..., "confirmations": [{"check_id",
"observable_type", "observable_value", "confirmed_at"}]}`. The template fields are `{probe}`,
`{observable}` (the confirmed values, comma-separated) and `{event_time}` (the latest
confirmation).

The candidate query uses the index on `external_remediation_check (probe_name, result,
update_time)`.

## Actions

An action runs on one alert with the trigger's evidence. It reports **done**, **skipped** (with a
reason) or **deferred**, or it raises, which counts as a failure (see *Runs and modes*). In
`dry_run` an action records what it would have done and changes nothing.

### `disposition`

```yaml
- type: disposition
  disposition: DELIVERY       # listed in dispositions:, and analyst_selectable
  comment: "..."              # optional
```

Calls `set_dispositions()` as the automation user (`global_settings.automation_user_id`), with
`expected_dispositions={OPEN}`, the trigger's re-check as `eligible`, and the rendered comment as
the comment. The alert's owner, its disposition and the trigger are all read under the row lock.
A disposition that the `dispositions:` block does not list, or one that is not
`analyst_selectable`, fails validation.

If `set_dispositions()` leaves the alert alone (an analyst took it, someone dispositioned it, or
the trigger no longer holds), the action is deferred. The rest of the rule's actions do not run.
If no action of the run had finished yet, the run is deleted, and the rule considers the alert
again on a later sweep.

DELIVERY is classified `tp`, so the alert's detections inherit a TP verdict, and SVS sample capture
runs in `dispositioned` mode as it does for any disposition. No event is created.

### `remediate`

```yaml
- type: remediate
  targets: same_message       # or evidence
```

For each target observable, the action takes `get_observable_remediation_targets()` and queues a
`remove` as the automation user. It skips a target that `removal_covers()` says is already being
removed or is gone.

- `targets: evidence` remediates the observables the evidence names, as they appear in the alert's
  tree.
- `targets: same_message` remediates every `email_delivery` in the alert whose message-id matches
  a confirmed delivery's, including deliveries a module added to the tree after the original ones.

An observable that yields no remediation target means the backstop does not exist for it. That is
logged at ERROR with the alert uuid and the observable, with an exception that names only the
observable type, so the operator who has to fix the remediation configuration gets an error report
once per type every ten minutes. An alert with no observable to remediate skips the action.

### `comment`

```yaml
- type: comment
  comment: "..."
```

Adds a comment to the alert as the automation user.

## Guards

These apply to every rule, and rule authors cannot turn them off.

- The alert's disposition is OPEN. A frozen disposition (SIMULATED) is never touched.
- Nobody owns the alert, or the automation user owns it. ACE never acts on an alert an analyst
  owns: no action runs and no run is recorded. The rule considers the alert again on each later
  sweep until the trigger's `max_age_hours` passes, so an alert the analyst unassigns while it is
  still OPEN gets acted on.
- Actions run in the order the rule lists them. A rule that dispositions should list `disposition`
  first, so that the ownership check under the row lock decides whether anything else runs.

Once an action of a run has finished, the alert is in the state the run put it in, so a retry of
that run's later actions skips the OPEN guard. The ownership guard still applies: a pending run on
an alert an analyst owns, or on an alert that was deleted, is left as it is, and each sweep logs
that at INFO.

## Runs and modes

`alert_automation_runs` records each rule's run on an alert: the rule name, the alert uuid, the
mode, the evidence, each action's outcome and attempt count, and timestamps. Its unique key is
`(rule_name, alert_uuid, mode)`, and the service inserts the row before any action runs. Each
action's outcome is saved as soon as it finishes, so a sweep that dies part way through a run
leaves a record of what it did.

- A rule acts at most once per alert and mode. Reopening the alert, or restoring the email, does
  not set it off again.
- An action that fails is logged with `logging.exception`, with `alert_uuid`, `rule`, `action` and
  `mode` in `extra`, and retried on later sweeps. Only unfinished actions are retried, so a
  disposition that already succeeded does not run again. After
  `service_alert_automation.max_action_attempts` attempts the action is marked failed, the run is
  marked failed, the rule's later actions never run, and that is logged at ERROR.
- `dry_run` evaluates the trigger and the guards, and records what each action would have done
  (the disposition and comment, the targets it would queue) without changing anything. `enforce`
  does it. Because the mode is part of the key, switching a rule from `dry_run` to `enforce` acts
  on the alerts the dry run saw if they are still OPEN and unowned.

Each action logs an INFO record with `alert_uuid`, `rule`, `action` and `mode` in `extra`.

A run is `pending` while an action is still to be tried, `done` once every action is done or
skipped, and `failed` once an action ran out of attempts, or once the rule's actions no longer
match the ones the run was started for (an edited rule; logged at ERROR).

A sweep claims a run before it runs any of its actions: the insert claims a new run, and a retry
claims a pending one with a conditional UPDATE on the version it read, which also sets a lease
(`RUN_LEASE_SECONDS` in `saq/alert_automation/runs.py`, ten minutes). Every later write of the run
is conditional on the version the sweep claimed. A sweep that finds the run claimed or changed
since it read it leaves it alone, and a sweep that dies leaves its run to the first sweep after
the lease runs out. A sweep that outlasts its lease and finds another one has claimed the run logs
that at ERROR and stops; the action it ran may then run twice.

## The service

`service_alert_automation` (`saq/alert_automation/service.py`, disabled by default, compose service
`alert-automation`) sweeps every enabled rule every `interval_seconds` (default 60). A sweep of a
rule first retries its pending runs, then reads the trigger's candidates `batch_size` at a time
with keyset paging on the alert uuid, and leaves out the alerts the rule already has a run on.

It runs on the primary node only and stays idle elsewhere, as `service_svs` does. If two instances
ever overlap, the runs table's unique key keeps them from starting a rule twice on an alert, and
the claim on a pending run keeps them from retrying it twice. It is not a queue service,
so it is clear of #1213. It installs no signal handlers, checks `is_shutting_down()` between
alerts, and waits on its own stop event.

## Reporting

```
ace alert-automation list [--rule NAME] [--mode MODE] [--since DATE] [--limit N] [--json]
ace alert-automation report --rule NAME [--since DATE]
```

`list` shows the runs, newest first. `report` compares a rule's dry-run decisions with what
happened to each alert afterwards. It counts the alerts analysts dispositioned the same way, the
ones they dispositioned differently (and lists those), the ones still open, the ones ACE itself
dispositioned, and the ones that were deleted. `--since` is a UTC date.

Analysts find automated dispositions in the GUI by disposition user (the automation user), and the
disposition review flow covers them.

## Adding a trigger or an action

A trigger or action type is a class that an `alert_automation` entry names. Core's entries are in
`etc/saq.default.yaml`. An integration appends its own from its `etc/saq.integration.yaml`, since
lists append when config files merge:

```yaml
alert_automation:
  trigger_types:
    - name: vendor_verdict                # rules use `type: vendor_verdict`
      python_module: vendor.automation
      python_class: VendorVerdictTrigger
  action_types:
    - name: vendor_ticket
      python_module: vendor.automation
      python_class: VendorTicketAction
```

The service imports the class when it loads a rule that names the type. An entry whose class
fails to import fails only the rules that use it.

A **trigger** subclasses `AlertAutomationTrigger` (`saq/alert_automation/rules.py`):

- `config_class`: a subclass of `TriggerConfig`, which rejects unknown keys. The rule's whole
  `trigger:` block is validated against it.
- `candidates(after, limit)`: at most `limit` `Candidate(alert_uuid, evidence)` in alert uuid
  order, after `after`, for alerts that have an `alerts` row. The evidence must be
  JSON-serializable.
- `still_holds(alert_uuids)`: the alerts the condition holds for now. It runs under the alerts'
  row locks, so it reads on a connection of its own (`private_transaction()`).
- Optionally, `template_fields` and `template_values(evidence)` for comment templates, and
  `evidence_observables(evidence)`, the (type, value) pairs `remediate` targets.

An **action** subclasses `AlertAutomationAction`:

- `config_class`: a subclass of `ActionConfig`.
- `run(context) -> ActionOutcome`: do the action, or, when `context.dry_run`, only say what it
  would do. Return `ActionStatus.DONE` or `SKIPPED` with a JSON-serializable `detail`, or
  `DEFERRED` when the alert changed and the rule should stop and try again later. Raise to fail;
  the action is retried.
- Optionally, `check(trigger)`, which raises `ValueError` when the action can't work with the
  rule's trigger (for example a template that names a field the trigger lacks).

`tests/saq/alert_automation/test_rules.py::FailingAction` is a minimal action registered this way.
