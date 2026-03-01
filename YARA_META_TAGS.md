# YARA Meta Tags

YARA meta tags allow analysis modules to annotate `FileObservable` instances with metadata that is passed to the YARA scanner. This enables YARA rule authors to constrain rules to specific file types using the `type` meta condition.

## How It Works

1. An analysis module calls `file_observable.add_yara_meta("type", "email.attachment")` after creating a file observable.
2. This stores a directive `yara_meta:type=email.attachment` on the observable.
3. When the YARA scanner processes the file, it reads `file_observable.yara_meta_tags` and passes them to the scanner as `meta_tags`.
4. YARA rules can then use `meta_tags` meta value to match only against files with specific type tags.

## Using Type Tags in YARA Rules

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
        ace_type and any of them
}
```

Multiple types can be targeted:

```yara
rule Suspicious_Script
{
    meta:
        meta_tags = "sub:type=script."
        description = "Detects suspicious patterns in any script type"

    strings:
        $s1 = "powershell" nocase

    condition:
        ace_type and any of them
}
```

## Type Taxonomy

### Email

| Type | Description |
|------|-------------|
| `email` | Raw RFC822 email files |
| `email.headers` | Extracted email headers |
| `email.combined` | Combined headers + body for scanning |
| `email.attachment` | Extracted email attachments |

### Scripts and Macros

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

### Documents

| Type | Description |
|------|-------------|
| `document.office` | Decrypted Office document |
| `document.pdf.object` | PDF parser extracted objects |
| `document.pdf.rendered` | Ghostscript rendered output |
| `document.pdf.text` | Plain text extracted by pdftotext |
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

### Executables

| Type | Description |
|------|-------------|
| `executable.unpacked` | UPX-unpacked executable |
| `executable.dotnet` | Deobfuscated .NET assembly (de4dot) |

### Archives and Disk Images

| Type | Description |
|------|-------------|
| `archive.dmg` | Converted DMG disk image |

### Network

| Type | Description |
|------|-------------|
| `network.smtp` | Raw SMTP stream |
| `network.http` | HTTP traffic files (Bro/Zeek) |
| `network.pcap` | PCAP conversation file |
| `network.pcap.text` | Tshark text output |
| `network.download` | CrawlPhish downloaded file |

### Payloads

| Type | Description |
|------|-------------|
| `payload.base64` | Base64-decoded command line payload |

### Certificates

| Type | Description |
|------|-------------|
| `certificate.x509` | X.509 certificate file |

### Metadata

| Type | Description |
|------|-------------|
| `metadata.exif` | EXIF metadata dump |
| `metadata.lnk` | LNK shortcut parsed to JSON |
| `metadata.shodan` | Shodan API results |
| `metadata.x509` | X.509 certificate metadata |

## Adding New Type Tags

When creating a new analysis module that produces file observables, add a type tag if the semantic type of the file is known at creation time:

```python
file_observable = analysis.add_file_observable(output_path)
if file_observable:
    file_observable.add_yara_meta("type", "script.newtype")
```

Guidelines:
- Use dotted-path hierarchy (e.g., `script.macro.vba`, `document.pdf.text`)
- Only tag files where the type is known. Do not tag files extracted from archives or user uploads where the content type is unknown.
- Always check that `add_file_observable` did not return `None` before calling `add_yara_meta`.
- Remember to update this file when you add new tags!
