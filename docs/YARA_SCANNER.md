# The YARA Scanner Service

The engine does not scan files with YARA itself. The `yara` service (`saq/yara_scanning/`) keeps a
pool of processes that hold the compiled rules, and the `YaraScanner_v3_4` analysis module
(`saq/modules/file_analysis/yara.py`) sends each file's path to them over a local unix socket.
The worker opens that path and reads the file contents itself. Rule
authoring is covered in [YARA_RULES.md](YARA_RULES.md); this document covers the service.

The `yara_scanner_v2` library still does the scanning: `YaraScanner` compiles and tracks the rules
and filters the results on rule meta. Up to library version 2.x the library also shipped the
client/server (`YaraScannerServer`, `ysc`, `yss`). That moved into ACE, and library 3.0.0 removed it.

## Processes

```
service process            YaraScannerServer: starts the manager, stops it
└─ manager                 owns the listening socket, watches the rules, runs generations
   ├─ generation G         compiles the rules once, forks the workers, restarts dead ones
   │  └─ worker × N        accept() on the shared listening socket and scan
   └─ generation G+1       only while it is replacing G after a rule change
```

- **One socket, many workers.** The manager binds a single listening socket and every worker
  accepts on it, so the kernel hands each connection to an idle worker. A client never waits
  behind a busy worker while another one is free.
- **Rules compile once per generation.** A generation compiles the rules and then forks its
  workers, so the compiled rules are shared copy-on-write instead of compiled once per worker.
- **A rule change has no downtime.** Every `update_frequency` seconds the manager checks the rule
  sources (`YaraScanner.rules_changed()`, which watches without compiling). On a change it starts
  a new generation and retires the old one only once the new one is serving. A retiring worker
  finishes the scan it is running and exits. Connections waiting in the socket's backlog are
  served by the new generation.
- **Broken rules never replace working ones.** A rule file that does not compile is logged and
  left out, as before. If no rules can be loaded at all (for example two files in one directory
  define the same rule name), the new generation fails, the old one keeps serving, and nothing
  is retried until the rules change again.
- **Crashes are contained.**
  - A dead worker is restarted by its generation, with a growing delay if it keeps dying.
  - A dead generation is restarted by the manager, with a delay that grows to 60 seconds.
  - `max_requests_per_worker` replaces each worker after that many requests, which contains
    any memory libyara leaks.
- **Stopping goes through pipes, not signals.** Each process is stopped through a control pipe
  its parent holds: the parent writes a byte and closes it, and a process whose parent dies sees
  EOF and stops too. The manager and everything
  under it form one process group. `stop()` waits up to `default_timeout + 4` seconds and then
  kills whatever is left of that group. `service_yara.shutdown_deadline_seconds` is 30 so this
  fits, and the config fails validation if `default_timeout` leaves too little room.

### The socket

The socket lives in `service_yara.socket_dir` (relative to `DATA_DIR`), so it must be on a
volume the scanner and the engines share. `scan_file` sends the path, and the worker reads
the file there, so every file that is scanned must be at the same path in both.

- The manager binds `scanner.sock.<pid>`.
- It publishes `scanner.sock` as a symlink to it only while a generation is serving.
- While nothing is serving (at startup, or after a generation died) there is no `scanner.sock`,
  so clients fail at once and scan locally.
- Sockets left behind by managers that are no longer running are removed at startup.

## Protocol

Every message is a frame: a 4 byte big-endian length followed by the payload
(`saq/yara_scanning/protocol.py`).

1. The server accepts and sends the single byte `A`. That byte is how the client tells "a worker
   took this" from "nothing is serving".
2. The client sends a JSON request: `{"v": 1, "op": "scan_file" | "scan_data", "path",
   "ext_vars", "meta_tags", "timeout"}`. `scan_file` carries the absolute path, and the worker
   opens that path and reads the file. `scan_data` follows the JSON with a frame of the raw
   bytes, capped by `max_data_bytes`. The analysis module and `ace yara scan` use `scan_file`.
3. The server answers with one JSON frame: `{"status": "ok" | "timeout" | "error" |
   "bad_request", "matches": [...], "error": {"type", "message"}}`.

Matched string data is binary. It travels as `[offset, identifier, base64]` and the client turns
it back into the `(offset, identifier, bytes)` tuple, so a match looks exactly like
`YaraScanner.scan_results`. Nothing is pickled in either direction.

## What the engine does when something fails

`saq/yara_scanning/client.py` raises a different exception for each outcome, and none of them is
an `OSError`:

| Exception | Meaning | `YaraScanner_v3_4` |
|---|---|---|
| `YaraServiceUnavailable` | No socket, connection refused, or no worker free within `client_queue_timeout` | Scans with a local `YaraScanner`, which it keeps until it has gone unused for `local_scanner_lifetime` minutes |
| `YaraScanTimeout` | YARA ran out of time, or there was no answer within the scan timeout + 5 seconds | Warning; the file counts as no match |
| `YaraScanCrashed` | A worker accepted the request and died before answering | Scan failure (`save_scan_failures` keeps a copy of the file). The file is **not** rescanned locally, where it could take the engine worker down the same way |
| `YaraScanError`, `ProtocolError` | YARA failed on the file, or the reply is invalid | Scan failure |

## Configuration (`service_yara`)

| Key | Meaning |
|---|---|
| `signature_dir`, `git_repo_dirs` | Where the rules are (see [YARA_RULES.md](YARA_RULES.md)) |
| `socket_dir` | Where the socket is, relative to `DATA_DIR` |
| `worker_count` | Number of workers; defaults to the CPUs this process may use |
| `update_frequency` | Seconds between checks for rule changes |
| `default_timeout` | Seconds one scan may take |
| `compile_timeout` | Seconds a new generation may take to compile before it is given up on |
| `io_timeout` | Seconds a worker waits on a client that stops sending or receiving |
| `client_queue_timeout` | Seconds a client waits for a free worker before it scans locally |
| `max_data_bytes` | Largest `scan_data` payload |
| `max_requests_per_worker` | Replace a worker after this many requests (0 = never) |
| `backlog` | `listen()` backlog |

## Operating it

```bash
ace service start yara        # what the yara container runs
ace yara scan FILE...         # scan through the running service (-j for the full matches)
```

`ace yara scan` replaces `ysc` and `ace service start yara` replaces `yss`. To test rules without
the service, use the library's own `scan` command.

The log lines to look for:

- `yara scanner generation N is serving` — a generation took over.
- `failed to start` — the rules did not load; the reason follows.
- `exited unexpectedly` and `restarting it in` — crashes.

## Next: QA matches

Matches from rules in QA mode (`modifiers = "qa"`, [YARA_QA.md](YARA_QA.md)) are still stored by
the analysis module, in the engine. The plan is to hand them from the workers to a consumer that
the manager owns, so that storing them never costs an engine worker anything. The seam is marked
in `saq/yara_scanning/server.py` (`_scan`).
