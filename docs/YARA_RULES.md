# Writing YARA Rules for ACE

This document describes how to write YARA rules that work with ACE, including the
ACE-specific meta directives, tags, and behaviors that go beyond stock YARA.

ACE scans files with YARA using the [`yara_scanner_v2`][yara_scanner] library
(installed as the `yara_scanner` module). That library adds a layer of
result-filtering meta directives on top of standard YARA, and ACE adds a further
layer of result *interpretation* on top of that. This document covers all three.

- Standard YARA syntax is documented in the upstream
  [YARA documentation](https://yara.readthedocs.io/).
- The scanner library and its CLI are documented in the
  [`yara_scanner_v2` README][yara_scanner].
- Everything ACE-specific is documented here.

[yara_scanner]: https://github.com/unixfreak0037/yara_scanner_v2/blob/main/README.md

## How YARA Scanning Works in ACE

YARA scanning is performed by the `YaraScanner_v3_4` analysis module
(`saq/modules/file_analysis/yara.py`). The important facts for a rule author:

- **Only files are scanned.** The module runs against `F_FILE` observables only.
  Remember that in ACE a `FileObservable`'s value is the SHA256 of the content;
  the human-readable name is `original_file_path`. Your rules match the file
  *content*, not its name (use the `file_name` / `full_path` meta directives below
  if you need to constrain by name).
- **Some files are skipped.** Zero-length files are skipped, as are files carrying
  the `no_scan` directive.
- **Rules live in namespaced directories.** Rules are loaded from
  `signatures/yara/<namespace>/*.yar`, where each subdirectory is a separate YARA
  namespace. The location is set by `signature_dir` in the `service_yara` section
  of `etc/saq.default.yaml` (default `signatures/yara`).
- **Rules auto-reload.** The scanner watches the rule directories and recompiles
  when files change (every `update_frequency` seconds, default 60). You do not
  need to restart anything to deploy a new or edited rule.
- **A match makes the file alertable.** When a rule matches (and it is not
  suppressed by a modifier — see below), the file becomes a detection point, the
  matched rule is added as a `yara_rule` observable, and the file is given the
  `sandbox` directive. If the file was decomposed from another file, the
  *original* file is the one marked for sandboxing.

## Anatomy of an ACE YARA Rule

```yara
rule M365_Tenant_Relay_Phish_PSE_Override
{
    meta:
        // give every rule a stable uuid; ACE turns it into a signature_id observable
        uuid = "4c3c8330-545d-4673-9a7c-7bd4597d0098"
        description = "Detects M365 tenant relay laundering ..."
        author = "John Doe"
        reference = "https://ace.com/ace/analysis?direct=..."
        // only scan files an ACE module has tagged as email headers (see below)
        meta_tags = "type=email.headers"

    strings:
        $arc_hop1  = "ARC-Authentication-Results: i=1;" ascii
        $fail_spf  = "spf=fail" ascii
        $pass_dkim = "dkim=pass" ascii
        $pse_high  = /PSE_S=([7-9][0-9][0-9]|1000)\b/ ascii

    condition:
        filesize < 5MB
        and $arc_hop1
        and $fail_spf
        and $pass_dkim
        and $pse_high
}
```

The `meta` block holds metadata, ACE control directives, and result-filtering
directives. The `condition` is ordinary YARA — note that **filtering directives
like `meta_tags` are not referenced in the condition**; they are applied to the
result *after* the condition matches.

## Standard YARA and ACE External Variables

Core YARA syntax — string definitions, modifiers (`nocase`, `wide`, `ascii`,
`fullword`, `xor`, …), regular expressions, hex strings, and the condition
language (`filesize`, `any of them`, `for` loops, etc.) — is unchanged. See the
[upstream YARA docs](https://yara.readthedocs.io/) for the full language.

ACE's scanner makes the following **external variables** available for use in rule
conditions:

| External    | Value                                              |
|-------------|----------------------------------------------------|
| `filename`  | the basename of the file being scanned             |
| `filepath`  | the full path of the file being scanned            |
| `extension` | the file extension                                 |
| `filetype`  | reserved; **not currently populated** (empty)      |

Example:

```yara
condition:
    extension == "ps1" and any of them
```

## Meta Directives That Constrain Matching

The scanner library supports a set of meta directives that act as **filters**: a
rule's strings/condition may match, but the result is *discarded* unless these
directives also agree with the file's properties. These are evaluated in
`filter_scan_results()` in the `yara_scanner` library.

| Meta directive | Compared against                                              |
|----------------|--------------------------------------------------------------|
| `file_ext`     | the file extension (everything after the last `.`)           |
| `file_name`    | the basename of the file                                     |
| `full_path`    | the full path of the file                                    |
| `mime_type`    | output of `file -b --mime-type` on the file                  |
| `meta_tags`    | tags supplied by the caller at scan time (see next section)  |

> **Important — these go in `meta:`, not `condition:`.** 

### Value syntax

All of these directives share the same value syntax:

- **Comma-separated lists** — the rule matches if *any* listed value matches:
  `file_ext = "exe, dll, ocx"`.
- **Negation** — prefix the whole value with `!` to invert the result:
  `file_ext = "!exe"` (match anything that is *not* an `exe`).
- **Regex** — prefix with `re:` to match by regular expression (case-insensitive):
  `file_name = "re:invoice[0-9]+\.doc$"`.
- **Substring** — prefix with `sub:` to match a case-insensitive substring:
  `mime_type = "sub:image/"`.

Prefixes combine in the order `!`, then `re:`/`sub:` — e.g. `mime_type = "!sub:image/"`
means "skip if the mime type contains `image/`". Plain matching is
case-insensitive equality.

Example — only scan PDF-ish files that are not already plain text:

```yara
rule pdf_dropper
{
    meta:
        file_ext = "pdf"
        mime_type = "!text/plain"
    strings:
        $s = "/JavaScript"
    condition:
        $s
}
```

## `meta_tags` and the ACE Type Taxonomy

`meta_tags` is the most important filtering directive in ACE. It lets a rule
declare which *kinds of files* it should run against, using a content-type
taxonomy that ACE's analysis modules attach to the files they produce.

### How it works

1. An analysis module annotates a file observable with a type, e.g.
   `file_observable.add_yara_meta("type", "email.attachment")`.
2. That stores a directive `yara_meta:type=email.attachment` on the observable
   (see `add_yara_meta` / `yara_meta_tags` in `saq/observables/file.py`).
3. When the YARA scanner processes the file, ACE reads
   `file_observable.yara_meta_tags` and passes the list (e.g.
   `["type=email.attachment"]`) to the scanner as its `meta_tags` argument.
4. A rule's `meta_tags` directive is then compared against that caller-supplied
   list, and the match is kept only if they agree.

### Matching semantics

The rule's `meta_tags` value (a comma-separated list, with the same `!` / `re:` /
`sub:` modifiers as above) is compared as a **cross-product** against every
caller-supplied tag: the rule matches if *any* rule value matches *any* caller
tag.

Two important edge cases:

- If a rule specifies `meta_tags` but the caller supplied **no** tags, the rule is
  **skipped** (the rule asked for a specific type and the file has none). A rule
  with **no** `meta_tags` directive runs against every file regardless of type.
- If the directive is **inverted** (`!`) and the caller supplied no tags, the rule
  is **not** skipped.

### Using type tags in rules

Match only VBA macro files:

```yara
rule Suspicious_VBA_Macro
{
    meta:
        meta_tags = "type=script.macro.vba"
        description = "Detects suspicious VBA macro patterns"
    strings:
        $s1 = "Shell" nocase
        $s2 = "WScript.Shell" nocase
    condition:
        any of them
}
```

Match any script type using a substring prefix:

```yara
rule Suspicious_Script
{
    meta:
        meta_tags = "sub:type=script."
        description = "Detects suspicious patterns in any script type"
    strings:
        $s1 = "powershell" nocase
    condition:
        any of them
}
```

### Type taxonomy

The types currently attached by ACE modules. Values are dotted-path hierarchies,
so a `sub:` match like `type=script.` will match every script subtype.

#### Email

| Type | Description |
|------|-------------|
| `email` | Raw RFC822 email files |
| `email.headers` | Extracted email headers |
| `email.combined` | Combined headers + body for scanning |
| `email.attachment` | Extracted email attachments |

#### Scripts and Macros

| Type | Description |
|------|-------------|
| `script.macro` | Generic Office macro |
| `script.macro.vba` | VBA macro code (olevba output) |
| `script.macro.xlm` | XLM macro output (xlmdeobfuscator) |
| `script.autoit` | Decompiled AutoIt script |
| `script.javascript` | JavaScript (extracted or deobfuscated) |
| `script.vbscript` | VBScript (pcodedmp output) |
| `script.encoded` | Microsoft Script Encoder decrypted output |
| `script.dotnet.decompiled` | .NET decompiled source (ILSpy) |
| `script.java.decompiled` | Java decompiled source (CFR) |

#### Documents

| Type | Description |
|------|-------------|
| `document.html` | HTML file |
| `document.office` | Decrypted Office document |
| `document.pdf` | PDF file |
| `document.pdf.object` | PDF parser extracted objects |
| `document.pdf.rendered` | Ghostscript rendered output |
| `document.pdf.text` | Plain text extracted by pdftotext |
| `document.rtf` | RTF file |
| `document.rtf.object` | OLE objects extracted from RTF |
| `document.rtf.stripped` | Whitespace-stripped RTF |
| `document.mhtml.part` | MHTML extracted parts |
| `document.html.embedded` | HTML data URL base64 payloads |
| `document.html.phishkit` | Phishkit rendered output |
| `document.activemime` | ActiveMIME extracted content |
| `document.onenote.embedded` | OneNote embedded files |
| `document.text.ocr` | OCR-extracted text from images |
| `document.text.qrcode` | QR code extracted URLs |
| `document.text.refanged` | Re-fanged IOC text |

#### Executables

| Type | Description |
|------|-------------|
| `executable` | Portable executable |
| `executable.unpacked` | UPX-unpacked executable |
| `executable.dotnet` | Deobfuscated .NET assembly (de4dot) |

#### Archives and Disk Images

| Type | Description |
|------|-------------|
| `archive.jar` | Java archive |
| `archive.dmg` | Converted DMG disk image |

#### Network

| Type | Description |
|------|-------------|
| `network.smtp` | Raw SMTP stream |
| `network.http` | HTTP traffic files (Bro/Zeek) |
| `network.pcap` | PCAP conversation file |
| `network.pcap.text` | Tshark text output |
| `network.download` | CrawlPhish downloaded file |

#### Payloads

| Type | Description |
|------|-------------|
| `payload.base64` | Base64-decoded command line payload |

#### Certificates

| Type | Description |
|------|-------------|
| `certificate.x509` | X.509 certificate file |

#### Metadata

| Type | Description |
|------|-------------|
| `metadata.exif` | EXIF metadata dump |
| `metadata.lnk` | LNK shortcut parsed to JSON |
| `metadata.shodan` | Shodan API results |
| `metadata.x509` | X.509 certificate metadata |

### Adding new type tags (for module authors)

When you write an analysis module that produces file observables, attach a type
tag if the semantic type of the file is known at creation time:

```python
file_observable = analysis.add_file_observable(output_path)
if file_observable:
    file_observable.add_yara_meta("type", "script.newtype")
```

Guidelines:

- Use the dotted-path hierarchy (e.g. `script.macro.vba`, `document.pdf.text`).
- Only tag files where the type is known. Do not tag files extracted from archives
  or uploaded by users where the content type is unknown.
- Always check that `add_file_observable` did not return `None` before calling
  `add_yara_meta`.
- The meta name must match `[a-zA-Z0-9_-]+`.
- Update the taxonomy table above when you add a new tag.

## ACE-Specific Meta Directives

These directives are interpreted by ACE itself (in
`saq/modules/file_analysis/yara.py`), not by the scanner library. They control how
a match is turned into observables, detection points, and alerts.

### `uuid`

A stable identifier for the rule. When present, ACE emits an `F_SIGNATURE_ID`
observable carrying the uuid, which lets analysts filter alerts in the GUI by rule.
Give every rule a `uuid` (any unique UUID).

```yara
meta:
    uuid = "4c3c8330-545d-4673-9a7c-7bd4597d0098"
```

### `enabled`

A kill switch. If `enabled` is set to a falsy value — `false`, `no`, `0`, `off`,
or `disabled` (string or native YARA value) — any match from the rule is dropped
*as if it never matched*. A file that matches only disabled rules behaves exactly
like a file with no matches. Omitting `enabled` (or any other value) leaves the
rule enabled.

```yara
meta:
    enabled = "false"   // temporarily silence this rule without deleting it
```

### `modifiers`

A comma-separated list of modifiers that change how the match is interpreted:

| Modifier         | Effect |
|------------------|--------|
| `no_alert`       | The rule still matches and still produces observables and tags, but it does **not** by itself make the file alertable and does **not** add a detection point. Useful for enrichment/tagging rules. |
| `qa`             | **QA mode.** Implies `no_alert`. In addition, ACE copies the matched file plus a JSON dump of the match into `qa_dir/<rule_name>/` for analyst review. Use this to vet a new rule against live data before letting it alert. |
| `directive=VALUE`| Adds the ACE directive `VALUE` to the scanned file (e.g. `directive=sandbox`). Skipped when the rule is also in `qa` mode. |

```yara
meta:
    modifiers = "no_alert, directive=extract_urls"
```

A file becomes an alert only if at least one matching rule does **not** carry
`no_alert`/`qa`.

### `queue`

Routes the detection point produced by the rule to a specific alert queue. The
value is passed through to the detection point when the rule (without `no_alert`)
fires.

```yara
meta:
    queue = "internal"
```

## Tags With Special Meaning

YARA rule tags (`rule Name : tag1 tag2 { ... }`) are all applied to the matched
file observable as ACE tags. Two tag values trigger additional behavior:

| Tag           | Effect |
|---------------|--------|
| `whitelisted` | The file (and its analysis) is **whitelisted** in ACE — i.e. suppressed. Use this to carve out known-good content. |
| `asm`         | Triggers **disassembly** of the matched bytes in the analysis view. The matched string's identifier selects the architecture by suffix (see below). |

When a rule is tagged `asm`, ACE disassembles the bytes around each matched string
based on the string identifier's suffix:

| String identifier suffix | Architecture |
|--------------------------|--------------|
| `...x86`                 | 32-bit x86   |
| `...x64`                 | 64-bit x86   |
| `...A32`                 | 32-bit ARM   |
| `...A64`                 | 64-bit ARM   |

```yara
rule shellcode_stub : asm
{
    strings:
        $stub_x64 = { 48 31 c0 ... }
    condition:
        $stub_x64
}
```

## Advanced Linkage Features

### `$obs_<id>` — for-detection observables

If a matched string is named `$obs_<N>` (where `<N>` is an observable database id),
ACE looks the observable up in the database, re-adds it to the analysis, and tags
it with the rule name. This is how rules generated from "for detection" observables
tie a YARA hit back to the original indicator. You normally do not write these by
hand — they are produced by ACE's tooling.

## Testing Rules Locally

The `yara_scanner` library ships a `scan` CLI you can use to test a rule against a
sample file before deploying it:

```bash
# scan a single file with a single rule
scan -y myrule.yar /path/to/sample

# emit full JSON results (rule, meta, strings, tags)
scan -j -y myrule.yar /path/to/sample | json_pp

# scan with caller-supplied meta tags (to exercise a meta_tags directive)
scan --meta-tags type=email.headers -y myrule.yar /path/to/headers.txt

# compile-only, to check a directory of rules for syntax/perf errors
scan -c -Y signatures/yara/bv
```

To deploy a rule to a running ACE instance, drop the `.yar` file into a
subdirectory of `signatures/yara/` — the scanner picks it up automatically within
`update_frequency` seconds.

For the complete CLI reference (recursive scanning, git-repo rule sources,
compiled-rule caching, and the rule performance-testing harness), see the
[`yara_scanner_v2` README][yara_scanner].

## Authoring Checklist

- Give every rule a unique `uuid`.
- Add a `description` and, where helpful, `author` / `reference` meta fields.
- Constrain expensive rules with a `filesize` guard in the condition and/or a
  `meta_tags` / `file_ext` / `mime_type` directive so they only run on relevant
  files.
- Prefer `meta_tags` (the ACE type taxonomy) to scope rules by content type rather
  than by file name.
- Vet new rules with the `qa` modifier against live data before letting them alert.
- Use `no_alert` for enrichment/tagging rules that should not, by themselves,
  create an alert.
- To permanently exclude a noisy rule from results without editing it, add its name
  to the blacklist file (`blacklist_path`, default `etc/yara.blacklist` — one rule
  name per line).
