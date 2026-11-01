# Integrations

An integration is a way to extend ACE in a structured way. The intention is to
allow you to easily build stuff for **your** environment without having to build
it directly into the core project.

This is an expiremental feature and subject to change as I figure out how I want
this to work.

## Goal

I want to be able to...

- Install an integration from a local directory.
- Enable and disable the integration.
- Add features to the application without having to modify the core project.

## Implementation Overview

- Integrations are subdirectories of (subdirectories of) the `integrations` directory.
- Each integration is it's own subdirectory.
- An integration directory can contain multiple integration directories.
- The presence of an `integration.md` file signifies that the directory is, in fact, an integration. This file serves as the documentation for it.
- The presence of an `install.sh` script is executed at image build time.
- The presence of a `src` directory is automatically appended to PYTHONPATH.
- The presence of a `etc` directory with the file `saq.integration.yaml` is automatically loaded.
- The presence of a `bin` directory is appended to PATH.
- See below for what happens with the `tests` directory.

## Instructions

To install an integration, simply copy (or clone) the integration directly into the integrations folder.

```bash
( cd integrations && git clone git@github.com:unixfreak0037/ace3-integrations.git )
```

Then rebuild the docker image and redeploy. The integration is enabled by default. You can use the ace cli to enable, disable and list the integrations.

```bash
ace integration --help # get the list of supported integration commands
ace integration list # list the status of all available integrations
ace integration enable NAME # enable the integration named NAME (requires restart)
ace integration disable NAME # disable the integration named NAME (required restart)

# (for pytest testing only)
ace integration install NAME # installs the integration name NAME (see Integration Tests)
ace integration uninstall NAME # uninstalls the integration name NAME (see Integration Tests)
```

## Integration Tests

This seems to be the trickiest part.

- I want the tests to have access to all the setup fixtures and utilities.
- pytest gets weird when loading from a deeply nested directory.

To solve this, for now, an integration has to be "installed". All this does is
create a symlink in the `tests` directory to the tests defined for the
integration. I know this is a bit of a kludge but it works.

## Development

Follow these steps to bulid a new integration.

1. Create a new subdirectory in the `integrations` directory.
1. Create an `integration.md` file to document your integration.
1. (optional) If your integration requires additional python or debian packages, or anything custom, create an `install.sh` file and make sure to `chmod 755 install.sh` so that it can be executed. This script is executed at image build time, so any changes made by this script are built into the final image.
1. Create a `src` directory to contain your python source code. Note that this directory is automatically included in the PYTHONPATH, so any modules defined in this directory are available.
1. (optional) Create a `bin` directory and include any additional executable binaries needed by your integration. Note this directory is automatically added to the PATH environment variable.
1. (optional) Create a `tests` directory for your tests. (See Integration Tests.)
1. Create an `etc` directory and put your configuration files in here.
1. (optional) Put executables in `etc/cron/hourly`, `etc/cron/daily` or `etc/cron/weekly` to run them on that schedule alongside ACE's own maintenance tasks, one file per task. See `docs/CRON.md`.
1. (optional) Add correlation hunt query sources or command types. See [Extending correlation hunts](#extending-correlation-hunts).
1. (optional) Add an alert router that decides which queue an alert goes to. See [Routing alerts](#routing-alerts).
1. (optional) Add API routes for your pages and actions to call. See [Adding API routes](#adding-api-routes).

You can use the example provided in `integrations.example` as a starting point to create a new integration.

## Integration Configuration

Each integration requires an integration configuration section, in a file named exactly
`etc/saq.integration.yaml`. 

```yaml
# each integration block starts with integration_NAME
# where NAME is a unique name for the integration
integration_example:
  name: example
  # required -- an integration with enabled: false is not imported
  enabled: true
  # a brief description of what the integration provides
  description: "Example Integration"
  # the python package to import
  python_module: example
  # extra keys are permitted and ignored
  author: unixfreak0037@gmail.com
  repo: https://github.com/unixfreak0037/ace3-example-integration
```

**The `integration_<name>:` block is mandatory.** 

ACE logs a warning at startup for any discovered integration directory that has no
`integration_*:` block.

## Extending correlation hunts

A correlation hunt (`docs/CORRELATION_HUNTS.md`) can be extended at two points. Both are
registered from your `etc/saq.integration.yaml` with a python module and class. Core's own
entries live in `etc/saq.default.yaml`, and yours are appended to them because lists append when
config files merge.

- A **query source** is a system that a `type: query` command can run a query against, named by
  the command's `source:`.
- A **command type** is a whole new `command.type`, for a correlation step that is neither
  "query a data source" nor "run a local script".

Both kinds of object are created once per process and shared by every hunt thread, so they must
be thread-safe. Build expensive clients lazily rather than in `__init__`: the object is created on
every node that loads hunts, including API nodes that only validate them. A constructor that
raises is logged, and every hunt that uses the name fails validation with that error.

### Query sources

```yaml
hunter:
  correlation:
    query_sources:
      - name: vendor            # hunts use `source: vendor`
        python_module: vendor.correlation
        python_class: VendorQuerySource
        kwargs: {}              # constructor arguments
```

Subclass `QuerySource` (`saq/collectors/hunter/correlation/registry.py`):

- Set `default_time_field` and `default_time_format` for the events the source returns.
- Implement `execute_query(query, start_time, end_time, timeout, source_options=None) -> list[dict]`.
- Optionally implement `format_timespec_for_display()`.

`saq/collectors/hunter/correlation/sources/splunk.py` is the reference implementation.

### Command types

With a command type registered, a hunt can do this:

```yaml
command:
  type: vendor_lookup
  timeout: 2m
  cache: 1d
  options:
    ip: "{{ _event.src_ip }}"
```

Register it:

```yaml
hunter:
  correlation:
    command_types:
      - name: vendor_lookup     # must match ^[a-z][a-z0-9_]*$
        python_module: vendor.correlation
        python_class: VendorLookupCommand
        kwargs: {}              # constructor arguments
```

`query`, `executable` and `defined` are reserved. If two integrations register the same name,
the one loaded last wins and a warning is logged.

Implement it by subclassing `CorrelationCommand` from
`saq/collectors/hunter/correlation/command_types.py`:

```python
import json

from pydantic import BaseModel

from saq.collectors.hunter.correlation.command_types import CommandContext, CorrelationCommand


class VendorLookupOptions(BaseModel):
    model_config = {"extra": "forbid"}  # so a typo in a hunt is a validation error
    ip: str
    limit: int = 10


class VendorLookupCommand(CorrelationCommand):
    config_class = VendorLookupOptions

    def execute(self, context: CommandContext, options: VendorLookupOptions) -> str:
        rows = get_vendor_client().lookup(options.ip, limit=options.limit,
                                          timeout=context.timeout.total_seconds())
        return "\n".join(json.dumps(row) for row in rows)

    def cache_key(self, context: CommandContext, options: VendorLookupOptions) -> dict:
        # the result depends only on the options, so share the cache across events
        return {"ip": options.ip, "limit": options.limit}
```

Core handles everything around the call, in this order:

1. It renders every string in the hunt's `options` with Jinja. Only `_event` and `_events` are
   available. Hunts have no access to configuration or secrets.
2. It validates the rendered dict against `config_class`.
3. It builds a `CommandContext` and applies `cache:`.
4. It calls `execute()`.
5. It sanitizes the output against the credential store.
6. It records the call on the correlation trace.

Any exception raised along the way is a step error. The event falls through to an alert and the
message is shown on the trace.

| Member | Default | Purpose |
|---|---|---|
| `config_class` | `None` | Pydantic model for `options`. `None` means the type takes no options. |
| `cacheable` | `True` | Set `False` if a result must never be reused. `cache:` then fails validation and is ignored at run time. |
| `render_options` | `True` | Set `False` to receive `options` verbatim, for a type whose option values contain literal `{{ }}`. |
| `execute(context, options) -> str` | abstract | Does the work. `options` is the validated `config_class` instance, or `{}` when there is none. |
| `cache_key(context, options) -> dict` | options + input | What identifies a call in the persistent cache. Core adds the type name. |
| `render_summary(context, options) -> str` | type + options JSON | The one-line trace entry, persisted into alert details. |

`CommandContext` carries these fields:

- `command_type`, `event`, `events`
- `transform_type` (`"event"` or `"stream"`)
- `hunt_start_time`, `hunt_end_time`
- `timeout` (a `timedelta`)
- `temp_dir`, the hunt's scratch directory, which is deleted after the step
- `config`, the raw merged configuration. Its `env:` and `file:` references are not resolved;
  `saq.configuration.yaml_parser.resolve_values()` resolves a section of it

Checklist:

- **Output.** Return a string that follows the built-in commands' output contract:
  - JSONL for a stream transform or `property_type: list`
  - JSON for `property_type: dict`
  - any string otherwise

  Return `""` for "no data" rather than raising. Raising makes the event alert.
- **Timeout.** Honor `context.timeout`. Core cannot interrupt a handler, so one that hangs wedges
  its hunt's thread.
- **Credentials.** Read them from your integration's configuration
  (`register_integration_configuration()`), never from `options`. Never put them in
  `render_summary()`.
- **Caching.** Only narrow `cache_key()` when the result does not depend on anything in the
  event beyond the options. The default includes the event, which is always correct but caches
  per event.
- **Validation.** `ace hunt verify` and `POST /api/v2/hunt/validate` check a hunt's custom
  commands against the registry and `config_class` on that node, so a hunt that names a type
  your integration does not provide there is caught before it runs.
- **Tests.** Call `register_command_type()` in a fixture and `clear_command_types()` after it.
  Drive the type through `saq.collectors.hunter.correlation.commands.execute_command` or
  `CorrelationEngine`, as `tests/saq/collectors/hunter/correlation/test_command_types.py` does.

`integrations.example/example/src/example/correlation.py` (`example_echo`) is a minimal working
example.

## Routing alerts

An **alert router** decides which queue an alert belongs in (`saq/alert_routing/`). Routers run
in every process that creates or analyzes alerts (engine workers, collectors, the API, the GUI
and the CLI), in ascending `priority`, and the first one that returns a decision wins. Core
ships one built-in router, `detection_queue` (priority 500), which routes a new alert to the
queue its detections' `queue` meta requests when every detection requests one, and configures
one more, `svs_marker` (priority 100), which routes alerts attributed to SVS test runs to the test
queue (`docs/SVS_RUNS.md`, *Attribution*). Register yours from `etc/saq.integration.yaml`; the list
is appended to core's `alert_routers` because lists append when config files merge:

```yaml
alert_routers:
  - name: vendor_router         # unique; recorded with every queue change it makes
    python_module: vendor.routing
    python_class: VendorRouter
    priority: 200               # below 500 runs before the detection queue router
    kwargs: {}                  # constructor arguments after name and priority
```

Subclass `AlertRouter` (`saq/alert_routing/router.py`): accept `name` and `priority` (and your
`kwargs`) in `__init__` and pass the first two to `super().__init__()`, and implement
`route(root, stage, final) -> RouteDecision | None`. A decision is `RouteDecision(queue, reason)`;
the registry fills in your router's name.

The two stages:

- **`RouteStage.PRE_INSERT`** runs inside `ALERT()`, the one function every alert insert goes
  through, before the `alerts` row exists. The decision becomes the alert's queue, in the row
  and in the saved tree, and is recorded in `alert_queue_changes`. Alerts the engine converts
  arrive here fully analyzed; alerts inserted at submission time (hunts, the API) arrive before
  any analysis.
- **`RouteStage.POST_ANALYSIS`** runs in the engine after each analysis pass over an existing
  alert, for routing evidence that only appears once the alert is analyzed. The decision moves
  the alert through `move_alert_to_queue()`, but only while it is `OPEN` and nobody has taken it
  (the automation user counts as nobody). An alert an analyst is working stays where it is.

`final` is `True` on the alert's last analysis pass: `POST_ANALYSIS` with no delayed analysis
outstanding, or after the engine aborted the analysis (a timeout or an exception), which abandons
what was delayed. Act on it for anything that must wait until a later pass can no longer change the
tree (a marker a delayed module may still find, say); don't read `root.delayed` for this, which
stays set after an aborted pass. It is always `False` at `PRE_INSERT`.

The contract:

- **A router never changes the tree.** It reads the root and returns a decision. The tree
  belongs to the caller (an engine worker, a collector, an API request), and the routed queue is
  the only change `ALERT()` or the engine makes on a router's behalf. A tag or detection belongs
  in an analysis module, which runs in the engine under the alert's lock and is indexed with the
  rest of the analysis. A router may write rows of its own (key them on the alert uuid: at
  `PRE_INSERT` the row has no id yet), in the caller's transaction or, better, in one of its own
  (`saq/database/private_session.py`): a failed write in the caller's transaction fails the
  caller's commit, which is the alert insert. `svs_marker` writes `svs_attributions` that way.
- **A router should not raise.** If it does, or returns anything but a `RouteDecision` or
  `None`, the exception is reported, the router is skipped and the next one runs. A router never
  breaks an alert insert or an analysis pass.
- **A router is shared by every thread of its process**, so `route()` must be thread-safe.
  Build expensive clients lazily.
- **A router is cheap when it has nothing to do.** It runs on every alert insert and every
  analysis pass over an alert.
- A router that fails to load (bad module, class or `kwargs`) is logged at startup, the others
  load, and `saq.alert_routing.get_alert_router_load_errors()` reports why.

To move an alert yourself (an analyst action, an API), call
`saq.database.util.alert.move_alert_to_queue(alert, queue, reason, auth, router=...)`, where `auth`
is the caller's `ApiAuthResult` (None for a router). It updates the row, records the move with who
made it, refreshes the alert's search payload and writes an AUDIT record with `log_audit()`; `get_last_queue_change(alert_id)` returns the newest move, which says what
queue the alert came from.

**Tests.** Call `saq.alert_routing.register_alert_router()` in a test and
`reset_alert_routers()` after it (`tests/saq/alert_routing/conftest.py` does this for every
test there), then call `route_alert(root, stage, final=...)` or `ALERT(root)`.

`integrations.example/example/src/example/routing.py` (`ExampleTagRouter`) routes a new alert
that carries one tag to one queue and does nothing to any other alert.

## Adding buttons to the alert toolbar

An integration adds a button to the alert page's toolbar with an **alert action**
(`saq/gui/alert_actions.py`), the alert-level counterpart of `register_observable_action()`.
Subclass `AlertAction` and register the class when your package is imported:

```python
from saq.gui.alert_actions import AlertAction, register_alert_action

class VendorAlertAction(AlertAction):
    name = "vendor_action"                       # [a-z0-9_]+, unique; the button is #alert_action_vendor_action
    description = "Vendor Action"                # the button's label, required
    icon = "lightning"                           # optional Bootstrap Icons name, without "bi-"
    action_path = "vendor/alert_action.html"     # included once on the page; wires the button up
    modifies_analysis = True                     # disabled while the alert is locked for analysis
    permission = ("alert", "write")              # hidden from users without it

    def is_available(self, alert) -> bool:      # shown only where it applies
        return alert.root_analysis.has_tag("vendor")

register_alert_action(VendorAlertAction)
```

- **The button does nothing by itself.** `action_path` is a template in your integration's
  templates, rendered once into the alert page's body, after the toolbar, with `action` and
  `alert` in its context. Put the button's modal and script there, and have the script call a
  route your integration adds to the API (see [Adding API routes](#adding-api-routes)). Check the
  permission again in the route: hiding a button is not access control. If the template is missing
  or fails to render, the button is left out and the error is logged.
- **`is_available()` runs on every render of the alert page**, so keep it cheap. If it, or the
  action's `__init__`, raises, the button is left out and the error is logged; the page still
  renders.
- Buttons appear after the core buttons, in registration order.

**Tests.** Patch `saq.gui.alert_actions._ALERT_ACTION_REGISTRY` to an empty list and register
your action, as `tests/app/analysis/views/test_index.py` does, then render the alert page.

## Adding cards to the alert page

An integration's alert template (one that extends `analysis/alert.html`) adds a collapsible card
with the `alert_section` macro (`app/templates/analysis/_alert_section.html`), not its own card
markup:

```jinja
{% from 'analysis/_alert_section.html' import alert_section with context %}
{% call alert_section('vendor_events', 'Vendor Events', default_open=false, summary='(3 events)') %}
    ...the card's body...
{% endcall %}
```

- **A collapsed section can still be found.** Its body is `hidden="until-found"`, so the
  browser's find-in-page searches it and opens it on a match. Nothing inside a Bootstrap
  `.collapse` can be found until someone opens it, because it is `display: none`.
- **Each analyst chooses how a section starts** with the pin in its header. The choice is stored
  per user under the section id (the `alert_sections` preference), so keep the id stable and
  unique on the page: `[a-z0-9_]`, at most 64 characters. `default_open` is how the section
  starts for an analyst who has not chosen.
- **A loop that renders one card per item** passes `instance` (the loop index, say). The cards
  share the analyst's choice but get their own element ids.
- **Sections nest**, so a card inside the Alert Details block is a section too. A collapsed
  `renderJsonTree()` node (`app/static/js/ace.js`) is also searchable, so raw events stay
  findable inside a collapsed section.

## Offering an alert template for manual analysis

The **Alert Template** list on the Manual Analysis page offers `analysis/alert.html` and the names
in `custom_alerts.selectable_templates`. Templates in `custom_alerts.dirs` are not offered unless
they are listed, because most of them read details only their own alert type has and fail on a
manual alert. List only a template that renders any alert's details. The default,
**Automatic**, stores no template, so the alert page looks one up for the `manual` alert type as
for any other alert: `analysis/alert.html`, unless the site has a `manual.html` in
`custom_alerts.dirs` or maps `manual` in `custom_alerts_backward_compatibility`. To offer an
integration's alert template there, append its Jinja name in the integration's config:

```yaml
custom_alerts:
  selectable_templates:
    - vendor/vendor_alert.html
```

A name the GUI cannot load is left out of the list and logged at ERROR with an error report. The chosen template is
stored in the alert's `alert_template` extension, which is how a hunt's `alert_template` setting
(`docs/HUNTS.md`) works as well. A submitted value that is not in the list is refused.

## Adding API routes

Anything an integration's pages, observable actions or alert actions fetch or change goes through
the API (`aceapi_v2`), not through routes in its Flask blueprint. Register the module that defines
your FastAPI router when your package is imported, and its routes are served under
`/api/v2/integrations/<name>`:

```python
# src/vendor/api/router.py
router = APIRouter()

@router.post("/alerts/{alert_uuid}/observables/{observable_uuid}/submit",
             response_model=ObservableAnalysisRequested, status_code=status.HTTP_202_ACCEPTED)
async def submit(
    alert_uuid: str,
    observable_uuid: str,
    auth: Annotated[ApiAuthResult, Depends(require_permission("observable", "write"))],
) -> ObservableAnalysisRequested:
    observable = await run_db_in_thread(service.request_submission, alert_uuid, observable_uuid)
    # saq.logging.log_audit: "AUDIT: ..." at INFO, with the caller's actor fields in extra={}
    log_audit("user %s requested a submission for observable %s in alert %s",
              auth.auth_name, observable, alert_uuid, auth=auth, alert_uuid=alert_uuid)
    return ObservableAnalysisRequested(message="Submission requested.")

# src/vendor/__init__.py
from aceapi_v2.integrations import register_integration_router

register_integration_router("vendor", "vendor.api.router")
```

- **Register the module's name, not the router.** Every ACE process imports your package, but only
  the API serves the routes. `vendor.api.router` (which must define `router`) is imported when an
  API app is built, so the other processes never load FastAPI or your router's service layer. A
  router module that fails to import is logged at ERROR and left out, and the API starts without
  it. Passing the router object still works, but it costs every process that import.

- **Every route needs a permission gate** (`require_permission()`, from `aceapi_v2/dependencies.py`).
  The `/integrations` prefix only requires a valid credential; `tests/saq/test_permission_catalog.py`
  fails on a route without a gate. Use an existing permission pair; the core route closest to
  yours shows which (an observable action that queues analysis is `observable:write`, one that
  only reads is `observable:read`).
- **Reuse the core services** rather than locking and loading alerts yourself.
  `aceapi_v2.alerts.service.request_observable_analysis(alert_uuid, observable_uuid, valid_types, change)`
  is what the core observable actions use: it locks the alert (409 while the engine holds it),
  checks the observable's type (422), applies `change` (add the directive your module waits for),
  and queues the alert in correlation mode, past the stop on dispositioned alerts.
  `load_observable(alert_uuid, observable_uuid)` loads one observable for an action that changes
  nothing. Both read the alert through the synchronous session, so call them through
  `run_db_in_thread()`.
- **Call the route from the template with `aceApi`** (`app/static/js/ace_api.js`), which prefixes
  `/api/v2`, sends the session cookie and rejects with the API's own error message:
  `aceApi.post("/integrations/vendor/alerts/{{alert.uuid}}/observables/{{_observable.uuid}}/submit")`.
- The router is registered once, under one name; registering another router under the same name
  is an error. Keep the Flask blueprint only for templates, static files and pages.

`integrations.example/example/src/example/api/router.py` is a working example.

**Tests.** Integration tests do not get the API client fixtures of `tests/aceapi_v2/conftest.py`
(conftest fixtures reach only their own directory), so import them into the test module:
`from tests.aceapi_v2.conftest import client, noperm_client, unauth_client, ...` along with the
fixtures those depend on (`_override_db_session`, `valid_api_key`, `test_user`, `session`,
`connection`, `engine`). The routes are served by the same app the core tests use.

## Notes

- Python analyzers in vscode/cursor have to be updated to reference the `src` directories in the integrations.
```javascript
// example .vscode/settings.json
{
    "python.analysis.extraPaths": ["integrations/example/src"],
    "cursorpyright.analysis.extraPaths": ["integrations/example/src"]
}
```
- An integration can be a whole separate git repository.
- The `integrations` directory is in .gitignore.
- The symlinks created for the tests are also in .gitignore.
