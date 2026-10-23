# third_party

Source code from other projects that ACE builds and ships, kept here because upstream is gone or
no longer maintained. Each directory keeps its own license, which is not necessarily ACE's.

## unautoit

The AutoIt script extractor that `AutoItAnalyzer` (`saq/modules/file_analysis/autoit.py`) runs as
`unautoit list` and `unautoit extract-all`. The `unautoit` stage of the `Dockerfile` runs libautoit's
tests and cross-compiles it for the architecture the image is built for.

- **UnAutoIt** by x0r19x91, GPLv3 (`unautoit/LICENSE`). The original repository,
  `github.com/x0r19x91/UnAutoIt`, no longer exists. This copy comes from the fork
  [digitalsleuth/UnAutoIt](https://github.com/digitalsleuth/UnAutoIt), commit `6c55d05`
  (UnAutoIt v1.1.1).
- **libautoit** v1.2.8 by x0r19x91, GPLv3, vendored in `unautoit/third_party/libautoit`. Its
  repository and its copy on proxy.golang.org are gone too. `unautoit/third_party/README.md` records
  where the source came from, its module hash, and the changes made to it.

ACE ships unautoit as a separate program and only runs it as a subprocess. No ACE code links
against it, so its GPLv3 license covers this directory and the binary built from it.

Changes from digitalsleuth/UnAutoIt `6c55d05`:

- `cmd/extract.go`, `cmd/extractAll.go`: the output directory is created with mode `0755`, not
  `0666`, which has no execute bit, so nothing could be written into it.
- `go.mod`: a `replace` directive points `github.com/x0r19x91/libautoit` at the vendored copy.
- libautoit: canonical word lookups go through a map instead of a scan of the whole word list,
  which is about 15 times faster, and string literals are no longer rendered with Go escapes
  (`"C:\Windows"`, not `"C:\\Windows"`). See `unautoit/third_party/README.md`.
- Not copied: `build/` (release binaries), `build.sh` and `build.ps1` (cross-compile scripts for
  those binaries; the `Dockerfile` builds unautoit instead), and `.idea/`.
