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
   ├─ qa recorder          records the spooled matches of rules in QA mode
   ├─ generation G         compiles the rules once, forks the workers, restarts dead ones
   │  └─ worker × N        accept() on the shared listening socket, scan, spool QA matches
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
  - A dead qa recorder is restarted by the manager the same way. Scanning never depends on it.
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
   "ext_vars", "meta_tags", "timeout", "qa"}`. `scan_file` carries the absolute path, and the
   worker opens that path and reads the file. `scan_data` follows the JSON with a frame of the raw
   bytes, capped by `max_data_bytes`. The analysis module and `ace yara scan` use `scan_file`.
   The optional `qa` object (`scan_file` only) says where the file came from: `{"root_uuid",
   "observable_uuid", "file_name", "file_size", "sha256"}`. Only a request that carries it has its
   QA matches recorded (see [QA matches](#qa-matches)). The analysis module sends it unless
   `save_qa_scan_results` is off; `ace yara scan` never does.
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
| `YaraServiceUnavailable` | No socket, connection refused, or no worker free within `client_queue_timeout` | Scans with a local `YaraScanner`, which it keeps until it has gone unused for `local_scanner_lifetime` minutes. QA matches found that way are logged and **not recorded** |
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
| `qa_spool_dir` | Where workers spool QA matches for the recorder, relative to `DATA_DIR` |
| `qa_spool_max_jobs` | The most jobs the spool may hold before new QA matches are dropped (0 = no limit) |

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
- `yara qa jobs waiting in` — the QA spool is not empty (logged at most once a minute).
- `the yara qa spool ... holds` — the spool is full and QA matches are being dropped.

## QA matches

Matches of rules in QA mode (`modifiers = "qa"`, [YARA_QA.md](YARA_QA.md)) are recorded by the
service, not by the engine, and never while a client waits. Recording one takes database
transactions and CAS puts that hash and encrypt the whole file, so it is split over two processes
that share only the spool directory, `service_yara.qa_spool_dir` (`saq/yara_scanning/qa.py`):

1. **The worker spools.** A `scan_file` request with a `qa` object whose scan matched an enabled
   QA rule with a `uuid` meta becomes a spool job:
   - Before the worker answers, it hardlinks the scanned file into the spool. The link keeps the
     bytes even if the engine deletes its file before they are recorded.
   - After it answered, it writes `<job>.json`: the `qa` object and the QA matches, encoded the way
     the protocol encodes them. It is written by rename, so it is the job's commit marker.
   - It never touches the database. A spooling failure is logged (at most once a minute per
     worker), and the scan is answered either way.
2. **The qa recorder records.** The manager runs one recorder process, independent of the
   generations, so a rule change never interrupts it. It drains the spool oldest first into
   `saq.yara_qa.store`, at a lower CPU priority (`nice` 10) than the workers.

**The spool has to be on the engine's filesystem.** A hardlink only works within one filesystem.
The default, `var/yss/qa_spool` under `DATA_DIR`, is on the same volume as the engine's storage in
docker. Where linking fails, the worker holds the file open while it answers and then copies it,
which costs the worker the copy.

**The spool is bounded.** Each worker counts the jobs in the spool (at most every 5 seconds) and
stops spooling once there are `qa_spool_max_jobs`, logging that QA matches are being dropped. That
holds while the recorder is down or the database is unreachable, when nothing else would stop the
spool, and the hardlinks it holds, from growing.

**What happens when something fails:**

| Failure | Result |
|---|---|
| The database is unreachable | The job is put back with the matches not recorded yet, and the recorder retries every 30 seconds. A job is dropped after 20 attempts, so a lasting error cannot hold up the jobs behind it |
| A match cannot be stored for another reason | Logged and reported; the job's other matches are still recorded |
| The recorder dies | The manager restarts it. A job it was recording (`<job>.claimed`) is dropped, so a job that crashes the recorder cannot crash it again and is never counted twice |
| The service stops | The recorder is told to stop first, finishes the job it is on, and is killed at the same deadline as the generations (a job it was killed in is dropped, as above). Jobs not recorded yet stay in the spool for the next start |
| A process dies while writing a job | The recorder removes the leftover `.file` or `.tmp` after 10 minutes |
| The engine scans with its local scanner | Nothing is spooled; the module logs each QA match as not recorded |

Recording is asynchronous: a QA match appears in the listing seconds after the scan, not by the
time the analysis module has its answer.
