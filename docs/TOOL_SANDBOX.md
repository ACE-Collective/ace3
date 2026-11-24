# Analysis tool sandbox

Analysis modules run external programs on the files in an alert. Most of those files come from an
attacker, and the programs that parse them (Ghostscript, exiftool, 7-Zip, unrar) have a history of
bugs that run code or write outside their output directory. Those programs run in the Landlock
sandbox (`saq/sandbox/`, the one tshark and correlation scripts use) through
`AnalysisModule.run_sandboxed_tool()`. A parser bug then gets a process that can read the one
file it was given and write only its own directories, instead of an engine worker that holds the
database passwords and `SAQ_ENC`.

The engine does not start these tools itself: the tool runner does (see *The tool runner* below),
and correlate `type: executable` commands run there too.

## What a tool can do

- It reads the file it analyzes (`target`), any `read_files` and `read_dirs` the module names, the
  directory its program is in, and the sandbox's fixed allowlist (`/usr`, the Python runtime, a
  few `/etc` files). Nothing else under SAQ_HOME, the data directory, `/auth`, `/home` or `/proc`
  is readable.
- It writes only a fresh, empty working directory under `tool_sandbox.work_dir` (its `HOME` and
  `TMPDIR`) and the `write_dirs` the module creates for it, such as an archive's `.extracted`
  directory.
- It has no network. `tool_sandbox.allowed_tcp_ports` is empty.
- Its environment holds `PATH`, `LANG`, `HOME`, `TMPDIR` and the module's `env`, never ACE's own.
- `tool_sandbox.memory_limit` bounds the memory it uses: it runs in a cgroup of its own whose
  `memory.max` is that limit, with no swap, and the kernel kills it, all of it, past that. Address
  space it reserves and does not use (a GC heap, a thread's arena) does not count, so a runtime
  needs no tuning to start.
- The rlimits in `tool_sandbox` bound it, along with the module's timeout and an output cap. Its CPU
  time limit is the timeout times the number of cores, because RLIMIT_CPU counts every thread and
  john, 7z and the JVM run one per core. Its cgroup's `pids.max` (4096) counts threads too, and is
  the ceiling for a fork loop that outruns `max_processes`, which is counted by polling. When it
  exits, times out or the analysis is cancelled (`should_stop()`), the launcher kills everything it
  started, and the runner then kills whatever is left in its cgroup (`cgroup.kill`).

ACE runs with SAQ_HOME as its cwd, and the paths it gives out for an alert's files are relative to
it. A tool runs in the same cwd, so those paths mean the same file to it, alone or inside a longer
argument like 7z's `-o<dir>`, and the module passes them as they are. Landlock grants access by
where a file is, not by the path it is opened with, so the tool still cannot list, read or write
anything under SAQ_HOME it was not given. A module that runs a tool somewhere else passes `cwd`,
and then makes the paths in its arguments fit it (unace extracts only into its cwd).

## Outputs

A tool that writes a single file writes it in its working directory. The module makes the directory
with `tool_workdir()`, gives the tool the file's path in it, and passes `workdir=` and
`outputs={"name": destination}`, `name` relative to the working directory. A tool told to write a
relative name writes in SAQ_HOME, which it cannot, and fails. Once the tool has finished, whatever
its exit status, each output it left as a plain file with one link is moved to its destination. A symlink or a hard link is
logged and dropped, because ACE would otherwise copy a file of its own into the alert. A tool that
was stopped keeps nothing. A tool that writes many files (an extractor, Ghostscript rendering
pages) writes them into a directory the module passes in `write_dirs`, and the module reads that
directory as hostile, as it did before.

## Failures

`run_sandboxed_tool()` returns `None` when it did not get a result:

- A timeout, too much output, more memory than `tool_sandbox.memory_limit` or a file larger than
  `tool_sandbox.file_size_limit` is the file's doing. It is logged at WARNING with the path, and the
  module sets `Analysis.error` to say the tool did not finish (`docs/ENGINE.md` §12.4). The runner
  reads a memory kill from the cgroup's `memory.events`, so it is reported as one whatever the tool
  printed.
  A file that hit the limit is cut off there, and the tool wrote nothing after it. unrar exits 5
  instead of dying, and keeps the file only with `-kb`, which both unrar extractions pass. The archive and encrypted-archive modules keep what was extracted, and
  their analysis says the extraction did not finish.
- A tool that ran and failed (exited with an error, or wrote nothing it should have) is a failed
  analysis too. `SandboxResult.failure_reason(tool)` words its `Analysis.error`: how the tool exited
  and the last line of its stderr (`tool_failure_reason()` for a tool that ran outside the sandbox).
  The module logs it at INFO with the path, since nothing else does.
- An archive listing is read even when it is longer than `tool_sandbox.max_output_bytes`
  (`partial_output`): an archive padded with entries has more files than any limit, so it is
  extracted under the file count limit, which takes the dangerous files first. The extractors run
  quiet, so the padding does not stop the extraction too.
- A cancelled analysis is logged at INFO.
- A tool the node cannot run at all is an operator's problem. That covers a tool runner that is
  not running, one that stopped during the run, one whose memory other runs held for all of the
  tool's time, one that could not create the run's cgroup, a program that is not found, a program
  in a directory that holds SAQ_HOME or the data directory, a program the sandbox cannot start
  (exit 125, 126 or 127 with no output), and a runtime it keeps from starting: the JVM, CoreCLR or
  OpenCV exits with its own start-up error (`startup_errors`) when a directory it needs is not
  readable. It is logged at ERROR on every file, and `ErrorReportHandler` writes its error report
  once per module, program and reason every ten minutes (`REPEAT_WINDOW_SECONDS` in
  `saq/error/reporting.py`). No tool runs outside the runner instead: that would put the tool back
  in the engine worker.

On a kernel older than 6.7 the TCP rule cannot be enforced and every tool fails. Set
`tool_sandbox.allowed_tcp_ports: null` there. A node without Landlock runs none of these tools: its
tool runner does not start.

## The tool runner

`saq/tool_runner/` is the `tool_runner` service (`service_tool_runner`), the `tool-runner`
container in `docker-compose.yml`. Every ACE process on the node sends it its sandboxed tools over a
unix socket in `service_tool_runner.socket_dir`: `run_sandboxed_tool()` and correlate executable
commands call `saq/tool_runner/client.py::run_on_runner()`, which takes what `build_sandbox_argv()` and
`run_sandboxed()` take. The runner reads no file it is given: the paths in a request mean the same
file on both sides, so the runner's container has the same volumes as its clients.

Each run gets a cgroup of its own (`saq/tool_runner/cgroup.py`), with `memory.max` the caller's
`memory_limit`, `memory.swap.max` 0, `memory.oom.group` 1 and `pids.max` 4096, and no RLIMIT_AS.
The launcher moves the tool into it before the exec (`--cgroup`). A run starts only once the memory
limits of the runs in progress, its own included, fit in the runner's container (its `memory.max`,
or the host's memory without one; give the container a `mem_limit` to bound it lower). A run waits
for that out of its own timeout, and one that would be left less than a second is answered busy.

No container may create cgroups as docker starts it: `/sys/fs/cgroup` is read-only in every
container that is not privileged. `docker/startup/delegate-cgroup.sh` starts the runner's container
as root with `CAP_SYS_ADMIN` and AppArmor unconfined, remounts `/sys/fs/cgroup` read-write, moves
every process into `tools/service`, enables the memory and pids controllers below `tools`, hands
`tools` to `ace`, and runs the service as `ace` with no capabilities. The capability stays on the
container, which is why it is this small container that parses nothing and holds no tool's input,
rather than `ace`, which holds the engine. A runner that cannot create cgroups, or has no Landlock,
does not start.

`dev` starts through the same script, because every pytest process runs a runner of its own
(`tests/harness.py`), with its socket in the session's temp dir: a `dev` created before this needs
`docker compose up -d dev`. `docker exec` into `dev` runs as root unless it is given `-u ace`, as
`bin/exec-in-container.sh` and `bin/attach-container.sh` give it.

The SVS YARA replay (`saq/svs/yara/replay.py`) and pcap dissection (`saq/modules/file_analysis/pcap.py`)
still run their sandboxed commands where they are, under RLIMIT_AS (`memory_limit` in their own
sandbox settings).

## Runtimes that need more

- .NET (de4dot, ilspycmd) will not start without its own `/proc/<pid>`. The modules pass
  `read_dirs=["/proc/self"]`, which setpriv resolves to the tool's own directory, because it execs
  the tool in the same process.
- `bin/qr_decode_opencv.py` exits with its own start-up error (`startup_errors`) when OpenCV cannot
  load.
- de4dot runs as `/opt/de4dotEx/de4dot` (`binary_path`), not through the `/usr/local/bin` wrapper,
  which execs a binary the sandbox would not let it read.
- A split archive does not extract without its other volumes. The archive module gives the
  extractor the files next to the first volume that are named as its other volumes are
  (`name.7z.002`, `name.part2.rar`, `name.r00`, `name.z01`, `name.c00`), as `read_files`, and never a
  symlink (`archive_volumes()`). The encrypted-rar module does the same. A hard link can be one:
  ACE links every file it stores into its `.hardcopy` store.
- unace opens the directory its archive is in, to look for other volumes, and fails when it cannot.
  It runs on a copy of the archive and its other volumes in a temporary directory of its own, so the
  sandbox never lets it list the alert's files.
- The JVM's `java.security` is under `/etc/java-<version>-openjdk`, which the module makes readable
  (`jvm_conf_dirs()`).

## Which tools

Sandboxed: `gs` (PDF rewriting, QR page rendering), `exiftool`, `pdftotext`, `pdfinfo`, `zbarimg`,
`bin/qr_decode_opencv.py` (OpenCV, on what `zbarimg` finds no QR code in),
`7z`, `unrar`, `unzip`, `unace`, `bin/unjar`, `dmg2img`, `upx`, `de4dot`, `ilspycmd`, the CFR
decompiler, `zip2john`, `rar2john`, `pdf2john.pl`, `office2john.py` and `john`
(`saq/cracking.py`). The encrypted-rar module extracts with a sandboxed `unrar` instead of
`rarfile.extractall()`, which runs unrar itself.

Not yet sandboxed: the Python parsers (officeparser3, pdf-parser, rtfobj, pcodedmp,
xlmdeobfuscator, jscript.decode.pl, unautoit), `file` and `node --check`. Each sandboxed run costs
about 60 ms, and `file` runs several times on every file. They still go through `run_tool()` or
`Popen`.
