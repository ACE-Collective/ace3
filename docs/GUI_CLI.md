# Running ACE CLI commands from the GUI

**Admin → CLI** (`/ace/admin/cli`) runs an ACE CLI command on one or more nodes and shows its
output as it arrives. You type what comes after `ace`. A leading `ace` is accepted and ignored.

## Who can use it

| permission | who holds it | what it allows |
|---|---|---|
| `admin:read` | the user | the admin area at all |
| `cli:execute` | the user | the page, `POST/GET /api/v2/cli/*`, and reading every recorded run and its output |
| `engine:cli` | the node key (the `automation` key's `engine:*`) | `POST /api/v2/engine/cli/{id}`: start a run that a user recorded for this node |

`cli:execute` is close to a shell on every node as the `ace` user, so grant it the way you would
grant one. Every run is recorded in `cli_executions`, with the user, node, command, exit code and
output, and logged at INFO as `AUDIT: user ... requested cli execution ...`. The record outlives
the user: deleting the user clears `user_id` and keeps the username. The command and output are
stored as is and readable by everyone holding `cli:execute`.

## How a run works

1. The page sends `POST /api/v2/cli/executions` with the command, the nodes (the primary node when
   none are given) and a timeout (default 300 seconds, at most 3600).
2. `http-api-v2` writes one `pending` row per node and asks each node, at its `nodes.location`, to
   start its own row: `POST /api/v2/engine/cli/{id}` with the automation key (`ace_api.start_cli_execution`).
   A node that cannot be reached, or that refuses, has its row marked `failed` with the reason.
3. That node's `http-api-engine` claims the row (`pending` → `running`, once, and only a row for
   itself), answers 202, and then runs `/venv/bin/python $SAQ_HOME/ace <command>` as a child
   process in an asyncio task, so the run holds no thread while it waits. A node runs at most 3
   commands at once (`MAX_RUNNING_PER_NODE`), because they share the container the engines transfer
   work through; beyond that it answers 429 and the run is `failed` with the reason.
4. The child's stdout and stderr, interleaved, are written to the row every 2 seconds and when it
   ends. The page polls `GET /api/v2/cli/executions/{id}`.

Only an id crosses node to node. The command always comes from the row a user wrote.

Because the child is the `ace` entry point itself, the GUI runs exactly the code a shell would,
including argparse's errors. The differences from a shell:

- There is no terminal: stdin is `/dev/null`, so a command that prompts (a password, a
  confirmation) fails. Use its non-interactive flags.
- Global options (`-c`, `-u`, `-p`, `-D`, ...) are refused, because they choose the config, the
  user or a debugger. Start with the command name. `--help` on its own is allowed.
- Options that take a secret are refused: `--password` (`user add`, `encryption set|test|encrypt|decrypt`),
  and under `encryption`, `-p` and `--value`. The command is stored and logged as typed, and it
  can't be redacted because the stored command is what the node runs. Set secrets on the
  **Secrets** and **Users** pages, or from a shell.
- The API's logging config (`ACE_LOG_CONFIG_PATH`) is removed from the child's environment, so
  the command logs to the console, that is, into its output.

## Statuses

| status | meaning |
|---|---|
| `pending` | recorded, not yet claimed by its node |
| `running` | the node is running it |
| `completed` | it exited; `exit_code` says how |
| `timed_out` | stopped at its timeout: SIGTERM to its process group, so ACE's own shutdown runs (an engine stops its own workers, which lead process groups of their own), then everything it started is killed, once it has stopped or 100 seconds later (longer than any service's shutdown deadline), whichever comes first |
| `failed` | it never ran: the node could not be reached or refused, or the command could not start |
| `abandoned` | nothing will finish it: the node's API stopped during the run, or a `pending`/`running` row is more than 180 seconds past its timeout |

Output beyond 1 MiB is read and dropped (`output_truncated`).

The command runs under the sandbox launcher (`saq/sandbox/launcher.py`, with `--unconfined`, so
without its Landlock domain), a child subreaper: whatever the command starts is reparented to it,
whatever session or group it moves to. When the command exits, the launcher kills everything it left
running; when it is stopped, the launcher gives the command its SIGTERM grace and then kills the rest.
The API signals only the launcher. The launcher is started through `setpriv --pdeathsig TERM`: if the
API worker dies without stopping it (SIGKILL, OOM), the command gets the same graceful stop, and
nothing keeps running with no one watching its deadline. The launcher also stops the command by itself
30 seconds after its timeout.

A command that runs until it is stopped (`service start`, `gui start`) runs until its timeout.
Long-running work belongs in a service or `etc/cron/`, not here.

## Code

- `aceapi_v2/cli/` — the `/cli` routes and the service that writes, dispatches, claims and runs rows
- `aceapi_v2/engine/router.py` — `POST /engine/cli/{id}`
- `app/admin/views/cli.py`, `app/templates/admin/cli.html`, `app/static/js/admin_cli.js` — the page
- `saq/database/model.py::CliExecution` — the table
