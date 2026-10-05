# Testing GUI changes in a browser

A development image (`BUILD_TYPE=development`, the default) ships a headless Chromium and two ways to drive it,
so that an agent (or a person) can check a GUI change in a real browser from inside the `dev` container:

- the Python `playwright` package in `/venv`, for scripted checks
- the `playwright-mcp` server (`@playwright/mcp`), which gives MCP clients (Claude Code, codex, cline) browser
  tools: navigate, click, type, accessibility snapshot, screenshot, console messages, network requests

Both use the same Chromium in `/opt/ms-playwright` (`PLAYWRIGHT_BROWSERS_PATH`). It lives outside `/home/ace`
because that directory is a named volume, which hides anything the image puts there. Production images
have none of this.

Everything below runs **inside the `dev` container**. The browser and the GUI must be in the same container:
the browser reaches the GUI on `localhost`.

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
    browser = p.chromium.launch()  # headless by default
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

Register the server with your agent inside the container. The registration is stored in `/home/ace`, which is
a volume, so it survives image rebuilds.

Claude Code:

```bash
claude mcp add playwright -- playwright-mcp --headless --browser chromium --ignore-https-errors --isolated
```

codex (`~/.codex/config.toml`):

```toml
[mcp_servers.playwright]
command = "playwright-mcp"
args = ["--headless", "--browser", "chromium", "--ignore-https-errors", "--isolated"]
```

- `--browser chromium` is required. The default is the Google Chrome channel, which is not installed.
- `--isolated` keeps the browser profile in memory, so every session starts logged out.
- Snapshots, console logs and screenshots go to `.playwright-mcp/` under the working directory, which is
  gitignored.

Then, for example: navigate to `https://localhost:5050/ace/login`, fill in analyst / analyst, open the page you
changed, take a snapshot, and check the console messages and network requests.

## Updating the browser tooling

`PLAYWRIGHT_VERSION` (pip) and `PLAYWRIGHT_MCP_VERSION` (npm) in the `Dockerfile` are pinned together. Pick the
pair so that the `chromium` revision in the pip package's `playwright/driver/package/browsers.json` matches
the one in `@playwright/mcp`'s bundled `playwright-core/browsers.json`. Otherwise the MCP server looks for a
Chromium build that was never installed.
