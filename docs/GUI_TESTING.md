# Testing GUI changes in a browser

An agent (or a person) can check a GUI change in a real browser from inside the `dev` container, in two ways:

- the Python `playwright` package in `/venv` (development images only), for scripted checks
- the `playwright-mcp` server (`@playwright/mcp`), which gives MCP clients (Claude Code, codex) browser
  tools: navigate, click, type, accessibility snapshot, screenshot, console messages, network requests

The headless Chromium both of them drive is not in the ACE image, which every ACE service runs. It is in an
image of its own (`docker/browser/Dockerfile`), which two compose services run:

| service | what it runs | reached from `dev` at |
|---|---|---|
| `browser-mcp` | `playwright-mcp` over HTTP | `http://localhost:8931/mcp` |
| `browser-server` | `playwright run-server`, for the Python package | `ws://localhost:3000/` |

Both are in the `browser` compose profile, so a plain `docker compose up` starts neither. Start them from the
host, or add `COMPOSE_PROFILES=browser` to `.env` to start them with the rest of the stack:

```bash
docker compose --profile browser up -d --build browser-mcp browser-server
```

They share the `dev` container's network namespace (`network_mode: service:dev`): the browser reaches a GUI
started in `dev` on `localhost`, `dev` reaches the two servers on `localhost`, and nothing is published to the
host. They rejoin it when `dev` is recreated by compose. They mount the checkout at `/opt/ace` as `dev` does and
run as the same user.

Everything below runs **inside the `dev` container**.

## Start the GUI

`ace gui start` runs the Flask GUI with werkzeug's reloader, so template and Python edits are picked up
without a restart. Start it in the background on a port nobody else is using, and keep its log:

```bash
source /venv/bin/activate && source /opt/ace/load_environment   # only if your shell did not source ~/.bashrc
cd /opt/ace
ace -L etc/logging_configs/debug_logging.yaml gui start --port 5050 > data/logs/gui-test.log 2>&1 &

# wait until it answers (it takes several seconds to load)
until curl -sk -o /dev/null https://localhost:5050/ace/login; do sleep 1; done
```

`ace` needs the virtualenv on `PATH`: without it the GUI dies at startup with `cannot find lnkparse used by
LnkParseAnalyzer`. Your shell has it if it sourced `~/.bashrc`. `docker compose exec dev bash -c ...` does not
source `~/.bashrc`, hence the first line.

- The GUI is at `https://localhost:5050/ace/`, with a self-signed certificate. Log in as **analyst / analyst**.
- Port 5000 is the one published to the host (as 5001). Use `--port 5000` instead when a person also wants to
  look at the page from the host.
- Stop the GUI with `pkill -f "gui start --port 5050"`. This also stops the reloader's child process and the
  private API server, if there is one. Don't run that `pkill` inside a `bash -c '...'` whose own command line
  contains the pattern, or it kills that shell as well.

### Testing API v2 changes too

The browser's own `/api/v2/*` requests (`app/static/js/ace_api.js` and similar) go through the GUI's proxy. By
default that proxy targets the shared `http-api-v2` container, which does not reload and serves whatever code
it started with. Add `--api-v2` and the GUI starts its own API server from this checkout instead:

```bash
ace -L etc/logging_configs/debug_logging.yaml gui start --port 5050 --api-v2 > data/logs/gui-test.log 2>&1 &
```

- It runs `uvicorn api_uvicorn:application --reload` on a free port on 127.0.0.1 (pick one with
  `--api-v2-port`), proxies `/api/v2` to it, and logs `API v2 for this GUI: http://127.0.0.1:<port>`.
- It reloads when anything under `aceapi_v2/` or `saq/` changes. Its access log (`"GET /users/me HTTP/1.1"
  200 OK`) and application log go to the same file as the GUI's, at the same `-L` level.
- It authenticates the browser's session cookie just as the shared server does, because both read the same
  config.
- It stops when the GUI stops, however the GUI is stopped: the kernel sends it SIGTERM when its parent exits.
- Flask views that call aceapi_v2 services in-process (`run_async_with_session()`) always run this checkout's
  code, with or without `--api-v2`.

### Logs

`-L` picks the logging config. Everything goes to the GUI process's stderr, which the command above sends to
`data/logs/gui-test.log`:

| config | level | format |
|---|---|---|
| `etc/logging_configs/debug_logging.yaml` | DEBUG | timestamp, logger, file:function:line, thread, pid |
| `etc/logging_configs/console_logging.yaml` (the default) | INFO | level and message only; also appends to `data/logs/console.log` |

Every request shows up as a werkzeug line (`"GET /ace/manage HTTP/1.1" 200 -`). A server-side exception shows
up as a traceback in this log, while the browser just gets a 500. Check both.

## Driving the browser with Python

```python
from playwright.sync_api import sync_playwright

BASE = "https://localhost:5050/ace"

with sync_playwright() as p:
    browser = p.chromium.connect("ws://localhost:3000/")  # the browser-server service
    page = browser.new_context(ignore_https_errors=True, viewport={"width": 1600, "height": 1000}).new_page()

    # collect anything that went wrong while the page was used
    problems = []
    page.on("console", lambda m: m.type in ("error", "warning") and problems.append(f"console {m.type}: {m.text}"))
    page.on("pageerror", lambda e: problems.append(f"page error: {e}"))
    page.on("requestfailed", lambda r: problems.append(f"request failed: {r.url} {r.failure}"))
    page.on("response", lambda r: r.status >= 400 and problems.append(f"HTTP {r.status}: {r.url}"))

    page.goto(f"{BASE}/login")
    page.fill("#username", "analyst")
    page.fill("#password", "analyst")
    page.click("button[type=submit]")
    page.wait_for_load_state("networkidle")

    page.goto(f"{BASE}/manage")
    page.wait_for_load_state("networkidle")
    print("title:", page.title(), "url:", page.url)
    page.screenshot(path="/tmp/manage.png", full_page=True)

    print("\n".join(problems) or "no problems")
    browser.close()
```

Run it with `/venv/bin/python`. Look at the screenshot with your image viewing tool. A screenshot only shows
that something rendered. To check what the page actually says, read it: `page.inner_text("table")`,
`page.locator(...).count()`, and so on.

`/tmp` in the container is a tmpfs, which `docker compose cp` cannot see. From the host, copy a file out with
`docker compose exec -T dev cat /tmp/manage.png > manage.png`.

## Driving the browser through MCP

Register the `browser-mcp` server with your agent inside the container. The registration is stored in
`/home/ace`, which is a volume, so it survives image rebuilds.

Claude Code:

```bash
claude mcp add --transport http playwright http://localhost:8931/mcp
```

codex (`~/.codex/config.toml`):

```toml
[mcp_servers.playwright]
url = "http://localhost:8931/mcp"
```

- The server's options (headless Chromium, HTTPS errors ignored, profile kept in memory) are set in its
  compose `command`, not by the client.
- Every client session gets a browser context of its own and starts logged out, so agents in different
  worktrees can use the one server at the same time.
- The server writes files under the client's *workspace*: the first MCP root the client sends, or the
  server's own working directory, `/opt/ace`, for a client that sends none. A client in a worktree that
  sends no roots therefore gets its files in the main checkout.
  - Files the server names itself (snapshots, console logs, a screenshot taken without `filename`) go to
    `.playwright-mcp/` in the workspace, which is gitignored.
  - A relative `filename` is resolved against the workspace itself, not `.playwright-mcp/`:
    `filename: "manage.png"` leaves an untracked `manage.png` in the checkout root. Pass
    `.playwright-mcp/manage.png` instead.
  - A path outside the workspace and `.playwright-mcp/` (`/tmp/manage.png`, a scratch directory) is
    refused with `File access denied`.
- An agent outside the `dev` container (Claude Code on the host) cannot reach the server.

Then, for example: navigate to `https://localhost:5050/ace/login`, fill in analyst / analyst, open the page you
changed, take a snapshot, and check the console messages and network requests.

## Updating the browser tooling

Three pins move together:

- `PLAYWRIGHT_VERSION` in `docker/browser/Dockerfile` decides the Chromium build the image installs.
- `PLAYWRIGHT_MCP_VERSION` there must be an `@playwright/mcp` whose bundled `playwright-core` uses the same
  Chromium revision (`browsers.json`). The image build fails when it does not, and names both revisions.
- `PLAYWRIGHT_VERSION` in the ACE `Dockerfile` (the pip package) must have the same major.minor version as
  the one in `docker/browser/Dockerfile`, or `connect()` is refused.

After a bump, rebuild the browser image (`docker compose --profile browser build browser-mcp`) and recreate both
services.
