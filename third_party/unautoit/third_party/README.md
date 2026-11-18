# third_party/libautoit

Source of `github.com/x0r19x91/libautoit` v1.2.8 (GPLv3, x0r19x91), with two
fixes applied (below). The upstream GitHub repository and the proxy.golang.org
copy are gone, so the module is wired in through the `replace` directive in
`../go.mod`.

- Source: https://goproxy.cn/github.com/x0r19x91/libautoit/@v/v1.2.8.zip
  (also mirrored at https://mirrors.aliyun.com/goproxy/)
- Module hash of that zip: `h1:t+FeR+oN0wxG3clOVG0Kx19GGY203U7JlXXjjuOku1k=`,
  identical to the entry in `../go.sum` and to the build info embedded in the
  released `UnAutoIt-windows-amd64.exe`.
- Omitted from the zip: `.idea/`, `build/*.exe`, and `tests/` (sample AutoIt
  executables and their dumps).

## Local changes

Made for ACE in October 2026; each modified file says so in its header. The two
test files, `lexer/scanner_test.go` and `tidy/clean_test.go`, are new.

### Word lookup performance

Restoring the canonical case of keywords, functions and macros scanned the
whole word list for every token, lowercasing both sides of each comparison
(3,401 user functions, scanned twice per call). `lexer/scanner.go` now builds
lowercase indexes once and looks words up in a map, also for `isPresent` in
`lexer/tokenizer.go`. Output is byte-identical; decompiling the 17k-line
`Clock.exe` test script went from ~1.4 s to ~90 ms. Covered by `TestCleanWord`.

### String literals

String literals were rendered with Go's `%q`, but AutoIt has no escape
sequences, so decompiled scripts had wrong string values (`C:\\Windows`,
`\t` instead of a tab, `\\d` in regexes). `lexer/scanner.go` now only doubles
quotes, and `tidy/clean.go` splits long literals on character boundaries and
re-quotes each piece (CR/LF become `@CR`/`@LF`). Covered by
`lexer/scanner_test.go` and `tidy/clean_test.go`; on the v1.2.8 test samples
every literal now matches Binary Refinery and AutoIt-Ripper.

## Provenance check

Rebuilding commit 54a7b5e with the unmodified source and Ubuntu 20.04's
`golang-1.13-go 1.13.8-1ubuntu1` at the original paths reproduces
`build/UnAutoIt-windows-amd64.exe` byte for byte
(sha256 `d771f7adc7882cf23a387434fbd0ab1902c0326df6035b2a239ebcbd256b52e9`).
