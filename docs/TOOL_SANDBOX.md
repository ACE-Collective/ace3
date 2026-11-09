# Analysis tool sandbox

Analysis modules run external programs on the files in an alert. Most of those files come from an
attacker, and the programs that parse them (Ghostscript, exiftool, 7-Zip, unrar) have a history of
bugs that run code or write outside their output directory. Those programs run in the Landlock
sandbox (`saq/sandbox/`, the one tshark and correlation scripts use) through
`AnalysisModule.run_sandboxed_tool()`. A parser bug then gets a process that can read the one
file it was given and write only its own directories, instead of an engine worker that holds the
database passwords and `SAQ_ENC`.

## What a tool can do

- It reads the file it analyzes (`target`), any `read_files` and `read_dirs` the module names, the
  directory its program is in, and the sandbox's fixed allowlist (`/usr`, the Python runtime, a
  few `/etc` files). Nothing else under SAQ_HOME, the data directory, `/auth`, `/home` or `/proc`
  is readable.
- It writes only a fresh, empty working directory under `tool_sandbox.work_dir` (its cwd, `HOME`
  and `TMPDIR`) and the `write_dirs` the module creates for it, such as an archive's `.extracted`
  directory.
- It has no network. `tool_sandbox.allowed_tcp_ports` is empty.
- Its environment holds `PATH`, `LANG`, `HOME`, `TMPDIR` and the module's `env`, never ACE's own.
- The rlimits in `tool_sandbox` bound it, along with the module's timeout and an output cap. Its CPU
  time limit is the timeout times the number of cores, because RLIMIT_CPU counts every thread and
  john, 7z and the JVM run one per core. When it exits, times out or the analysis is cancelled
  (`should_stop()`), the launcher kills everything it started.

ACE's paths are often relative to SAQ_HOME. An argument equal to `target`, a `read_files` entry or a
`write_dirs` entry is made absolute. A path inside a longer argument, like 7z's `-o<dir>`, is the
module's to make absolute.

## Outputs

A tool that writes a single file names it relative to its working directory, and the module passes
`outputs={"name": destination}`. Once the tool has finished, whatever its exit status, each output
it left as a plain file with one link is moved to its destination. A symlink or a hard link is
logged and dropped, because ACE would otherwise copy a file of its own into the alert. A tool that
was stopped keeps nothing. A tool that writes many files (an extractor, Ghostscript rendering
pages) writes them into a directory the module passes in `write_dirs`, and the module reads that
directory as hostile, as it did before.

## Failures

`run_sandboxed_tool()` returns `None` when it did not get a result:

- A timeout, too much output or a file larger than `tool_sandbox.file_size_limit` is the file's
  doing. It is logged at WARNING with the path, and the module sets `Analysis.error` to say the tool
  did not finish (`docs/ENGINE.md` §12.4).
  A file that hit the limit is cut off there, and the tool wrote nothing after it. unrar exits 5
  instead of dying, and keeps the file only with `-kb`, which both unrar extractions pass. The archive and encrypted-archive modules keep what was extracted, and
  their analysis says the extraction did not finish.
- A tool that ran and failed (exited with an error, or wrote nothing it should have) is a failed
  analysis too. `SandboxResult.failure_reason(tool)` words its `Analysis.error`: how the tool exited
  and the last line of its stderr.
- An archive listing is read even when it is longer than `tool_sandbox.max_output_bytes`
  (`partial_output`): an archive padded with entries has more files than any limit, so it is
  extracted under the file count limit, which takes the dangerous files first. The extractors run
  quiet, so the padding does not stop the extraction too.
- A cancelled analysis is logged at INFO.
- A Landlock probe that could not run (a fork that failed under load) is logged at ERROR with its
  traceback, and the tool is skipped with a WARNING. The next call probes again.
- A tool the node cannot run at all is an operator's problem. That covers a node without Landlock, a
  program that is not found, a program in a directory that holds SAQ_HOME or the data directory,
  a program the sandbox cannot start (exit 125, 126 or 127 with no output), and a runtime it keeps
  from starting: the JVM, CoreCLR or OpenCV exits with its own start-up error (`startup_errors`) when a
  directory it needs is not readable or the memory limit is too small for it. It is logged at ERROR
  with an error report once per module and program per process, then at WARNING.

On a kernel older than 6.7 the TCP rule cannot be enforced and every tool fails. Set
`tool_sandbox.allowed_tcp_ports: null` there. A node without Landlock runs none of these tools.

## Runtimes that need more

- .NET (de4dot, ilspycmd) will not start without its own `/proc/<pid>`. The modules pass
  `read_dirs=["/proc/self"]`, which setpriv resolves to the tool's own directory, because it execs
  the tool in the same process. The .NET GC reserves 256 GB of address space unless it gets
  `DOTNET_GCHeapHardLimit` and `DOTNET_GCRegionRange`, and even then the runtime reserves about
  5 GB, so these tools run with a 12 GB `memory_limit`. The heap limit bounds what they use.
- numpy's OpenBLAS starts a thread per core, and each reserves address space under the memory
  limit, so `bin/qr_decode_opencv.py` runs with `OPENBLAS_NUM_THREADS=1`. It exits with its own
  start-up error (`startup_errors`) when OpenCV cannot load.
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
- The JVM gets `-Xmx1g` and fixed class space and code cache sizes. Without them it fails to
  reserve its metaspace under the 4 GB limit about one start in three. Its `java.security` is under
  `/etc/java-<version>-openjdk`, which the module makes readable (`jvm_conf_dirs()`).

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
