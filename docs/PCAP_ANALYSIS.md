# PCAP analysis

ACE dissects pcap and pcapng files with tshark (Wireshark's CLI) and turns what the capture carried
into observables: hosts, DNS names, TLS server names, JA4 fingerprints, certificates, HTTP requests
and the files that crossed the wire. When a TLS key log is anywhere in the analysis tree, it also
decrypts the TLS sessions and adds what was inside them.

Code: `saq/modules/file_analysis/pcap.py`. Tests and fixtures:
`tests/saq/modules/file_analysis/test_pcap.py`, `tests/saq/modules/file_analysis/test_pcap/`.

## The analysis tree

A capture can hold thousands of names and addresses, so nothing hangs directly off the pcap file.
Each kind of result has its own analysis node under the pcap, every node is collapsed by default
(`default_collapsed: true`), and a node that would be empty is not created:

```
capture.pcapng
 ├─ PCAP Analysis          pcap_analyzer        packets, flows and endpoint tables; IPs, MACs, hostnames
 ├─ PCAP DNS               pcap_dns             names with their answers and query/response counts; FQDNs and answer IPs
 ├─ PCAP TLS               pcap_tls             sessions (server, SNI, JA4, certificate subject/SAN/issuer); FQDNs, JA4, certificate files
 ├─ PCAP HTTP              pcap_http            requests; URLs, Host FQDNs, User-Agents
 ├─ PCAP Files             pcap_files           files carved from HTTP, SMB, FTP-data, TFTP and IMF
 └─ PCAP TLS Decryption    pcap_tls_decryption  only what the decrypted traffic adds beyond the above
sslkeylog.txt
 └─ TLS Key Log            tls_keylog           secret counts by label (never the secrets); tag tls_keylog
```

- DNS answer IPs carry a time: the packet time of the first DNS response that returned them (as a
  hunt's `time: true` does). A timed observable is distinct from the same value without one, so an
  answer IP that was also contacted appears both under PCAP DNS (timed) and in the hosts (untimed),
  each analyzed. Using the first response keeps it to one timed observable per IP.
- IP addresses, MAC addresses and hostnames are added `volatile`, so they are hidden unless the
  analyst selects "Show All Observables" or they lead to a detection. Everything else is visible.
- In the node tables, JA4 (TLS), URL (HTTP), file name, SHA256 and URL (Files), and the hostnames, IP
  and MAC addresses and flow endpoints of PCAP Analysis are links that
  pivot to every alert containing that observable, exactly like clicking it in the alert tree. A
  file name pivots on the file's content: a file observable's value is its sha256. An address the
  module never adds as an observable (multicast, broadcast, loopback, link-local) stays plain text.
- Within a node, observables sort by type (files, URLs, FQDNs, JA4, User-Agents, hostnames, IPs, MACs).
- Display types say where an observable came from: `DNS Query Name` (a name looked up), `DNS CNAME
  Target`, `DNS Zone (SOA/NS)` (the owner of an SOA or NS record, usually from the authority section
  of a reply with no answer), `DNS Record Name` (any other record owner), `DNS Answer IP`, `TLS SNI`
  (a server name only seen in a TLS hello, never in DNS), and for JA4 the sessions' destinations,
  e.g. `JA4 client fingerprint (TLS ClientHello), seen to www.example.com, cdn.example.net,
  login.example.org, +9 more` (the SNI, or the
  server address when there is none). An observable has one display type wherever it appears in the
  alert, so the pcap modules never replace one another module set: a name that is also a certificate
  SAN shows `Certificate SAN DNS Name` under PCAP DNS too.
- Every table page starts with the capture it came from (`capinfos`, run in the sandbox: file name,
  format, size, link types and interfaces, packet count, first to last packet time in UTC, and the
  application that wrote it), and every table says how its rows are ordered. DNS, TLS, HTTP and
  hostname rows are in capture order, called chronological only when `capinfos` reports the packets
  in strict time order; carved files are by protocol and name (tshark's object export does not
  record when an object crossed the wire); endpoints and flows are by volume.
- Not added: multicast, broadcast, unspecified, link-local, loopback and reserved IPs; group
  (broadcast/multicast) and all-zero MACs; names ending in `excluded_fqdn_suffixes` (`.arpa`,
  `.local` by default).
- Each node adds at most `max_observables_per_type` observables of one type and keeps at most
  `max_table_rows` rows per table; the analysis details and its page say how many were left out.
  The root-wide `maximum_observable_count` still applies on top of this.
- Carved files and certificates are linked to the pcap with `extracted_from`. An HTTP object is
  linked to its URL with `downloaded_from` when exactly one request in the capture has a path
  ending in its file name. Certificates become file observables, so `x509_analyzer` adds their
  CN/SAN names. Carved files go through the rest of file analysis (yara, file type, email parsing
  for IMF, and so on).

## How it runs

`pcap_analyzer` recognizes a capture by its magic number (`is_pcap_file()`), never by its name,
and runs three tools in the Landlock sandbox:

1. `capinfos -M -S` for the capture metadata on every table page, bounded by a fixed 30 s since it
   only reads record headers (a failure only loses the page header);
2. tshark `-q -z io,stat,0 -z endpoints,... -z conv,...` for the packet count, the endpoints and the flows;
3. tshark `-T json -Y <filter> -e <fields> --export-objects ...` for DNS, TLS handshakes, HTTP(/2)
   headers, DHCP and NBNS, plus the exported objects. Certificates are taken from the handshake bytes.

Each tshark run is bounded by `tshark_timeout` (240 s), so the three fit in `pcap_analyzer`'s
`maximum_analysis_time` (600 s).

The JSON of the third run is about 1 kB per matching packet and has to fit under the sandbox's output
cap (`sandbox.max_output_bytes`, 64 MiB), so its display filter also takes only the first
`max_field_packets` (50,000) packets of the capture (`frame.number <= N`). tshark still reads every
packet, so the endpoints, the flows and the carved files cover the whole capture; only the DNS, TLS,
HTTP and hostname tables (and their observables) come from the start of it. When the capture is
longer, those tables say "Read from the first 50,000 of the capture's N packets only" and the module
logs it at INFO.

Carved files and certificates are written beside the capture in the alert's storage, in
`<capture>.pcap_objects/` (and `<capture>.pcap_decrypted/` for decryption), never `<capture>.extracted/`,
which belongs to `archive`. `archive` skips anything `is_pcap_file()` recognizes: libmagic calls a pcapng
`application/octet-stream`, which its mime exclusions cannot catch, and 7z "extracts" junk from one.
`hidden_mime` skips captures too: an email in the capture is carved as an IMF object, while a MIME
body found in the raw capture bytes is broken up by packet headers.

The result is the capture *index*, kept in `PcapAnalysis.details`. The category instances
(`pcap_dns`, `pcap_tls`, `pcap_http`, `pcap_files`: one class, `PcapCategoryAnalyzer`, configured
once per `category`) wait for it and read it; they never run tshark.

tshark's dissectors parse hostile bytes, so tshark only ever runs through
`saq/sandbox/runner.py`: a private working directory (holding a copy of the capture, never a
link, so tshark cannot change the evidence), nothing
of ACE readable, no network (`sandbox.allowed_tcp_ports` stays empty), rlimits, a `tshark_timeout`
and an output cap. On a node without Landlock the module refuses to run tshark and records an
error rather than running it unsandboxed. Every failure is recorded in the analysis `error` and
shown in its summary, for the analyst. A failure of the capture itself (tshark cannot read it, a
timeout, too much output) is the analyst's to see and is logged at INFO only. Anything else,
including a node without Landlock, which cannot dissect any capture, is logged at ERROR with an
error report through `log_loop_exception`. A capture cut short mid-packet is dissected as far as
it goes.

## TLS decryption

Decryption needs the session secrets in the NSS key log format that browsers and curl write to
`SSLKEYLOGFILE` (`CLIENT_RANDOM`, the TLS 1.3 `*_TRAFFIC_SECRET` labels, `RSA`, ...).

- **Finding key logs.** Any file in the tree whose first lines (comments and blank lines aside) are
  key log lines is a key log, whatever it is called (`is_keylog_file()`), up to
  `max_keylog_size`. Only valid key log lines are passed to tshark.
- **When.** `pcap_tls_decryption` runs in final analysis, after everything else in the tree has
  been analyzed, so a key log extracted from an archive, or carved from another capture, is already
  there. It is only created for a capture that has TLS sessions; with no key log its summary says
  so. It merges every key log in the tree, runs tshark again with `-o tls.keylog_file:...`, and adds
  only the observables the plaintext index did not already have (decrypted URLs, carved files, TLS
  1.3 certificates, ...). The summary reports how many of the capture's TLS sessions had keys,
  matched by client random.
- **A key log added later.** When an analyst adds a key log to an alert whose decryption analysis
  already completed, `tls_keylog` sees a completed `PcapTlsDecryptionAnalysis` that has not used
  it and, if the new key log has keys for sessions in that capture that were not decrypted yet,
  decrypts the capture again with every key log in the tree. The result is added to the existing
  node, never in place of it: the rows of its tables are kept and the new ones are appended, so the
  files an earlier key log carved stay listed. Applying the same key logs twice adds nothing.
  There is one tshark run per capture, all inside `tls_keylog`'s `maximum_analysis_time`. A capture
  whose run would no longer fit is skipped rather than risking the worker. The key log's summary
  says "not applied to N pcaps (out of time)" and the module logs it at INFO.
- **Embedded secrets.** A pcapng can carry its own keys in Decryption Secrets Blocks (Wireshark
  writes them when saving a capture taken with a key log, or `editcap --inject-secrets` adds them).
  tshark decrypts with them on its own, so the plaintext pass already sees inside TLS: the HTTPS
  URLs and files appear under PCAP HTTP and PCAP Files, not under PCAP TLS Decryption.
  `read_embedded_secrets()` finds the blocks by reading only block headers, and the capture is
  called out for the analyst: the pcap gets a tag per kind of secret (`pcap_embedded_tls_keys`,
  `pcap_embedded_ssh_keys`, `pcap_embedded_wireguard_keys`, ...), PCAP Analysis says
  "decryption keys embedded (TLS keys for N sessions)" and lists the secret types, and PCAP TLS
  Decryption counts those sessions as "embedded in the capture". A separate key log then only
  triggers another tshark run if it has keys for sessions the embedded ones did not cover.

## Limits

- HTTP/2 (most decrypted HTTPS): request URLs come from the `:authority`/`:path` headers, but tshark
  4.4 cannot export HTTP/2 bodies, so no files are carved from it.
- JA4 fingerprints the client (its TLS ClientHello), not the server: every session from the same
  browser has the same JA4 whatever site it went to, so a phishing page and a legitimate site
  visited by one browser share it. The TLS page says so above its table.
- JA4 is the only fingerprint added (tshark computes it). JA3/JA3S are not added; the rest of the
  JA4+ family is under the FoxIO license and not implemented.
- No auto-crawl of certificate names: a certificate in a capture was only observed, not fetched, so
  the carved certificate files carry `DIRECTIVE_NO_CRAWL`. `x509_analyzer` still extracts their
  CN/SAN FQDNs, SAN IPs, sha256 and the X509 detail tree, but does not add the `crawl` URLs that
  would otherwise send every certificate name (every SAN, and CA certificates) to phishkit. The HTTP
  URLs actually seen in the capture are added normally; an analyst can still crawl any URL by hand.
- `archive` does not extract pcaps from archives (`excluded_mime_types` lists
  `application/vnd.tcpdump.pcap`); a capture inside a zip is not dissected.
- No analysis caching (`cache_ttl` unset): `tls_keylog` changes another observable's analysis,
  which the cache cannot replay.

## Configuration

The settings every pcap module shares are set once, in the top-level `pcap:` section of
`etc/saq.default.yaml` (`PcapConfig` in `saq/configuration/schema.py`): `tshark_path`,
`tshark_timeout`, `work_dir`, `sandbox`, `max_file_size`, `max_keylog_size`, `max_table_rows`,
`max_field_packets`, `max_extracted_files`, `max_observables_per_type`, `excluded_fqdn_suffixes`.
A module's own block (`analysis_module_pcap_*`, `analysis_module_tls_keylog`) holds only what is
its own: `maximum_analysis_time`, and `category` for the category instances. The modules are in
the `file` module group.

`max_table_rows` only limits the rows kept for display. Key logs are matched against every TLS
session in the capture, from the full list of client randoms kept in `PcapAnalysis.details`.

The `tshark` package is installed in the image (`Dockerfile`).

## Test fixtures

`tests/saq/modules/file_analysis/test_pcap/generate_fixtures.sh` regenerates every fixture inside the
dev container: `network.pcap` (hand-built DHCP/NBNS/DNS frames from `synthesize_frames.py`),
`http_tls.pcapng` (a loopback capture of plain HTTP plus TLS 1.2 and TLS 1.3 requests to `*.example`
names), its `sslkeylog.txt`, and `http_tls_dsb.pcapng` (the same capture with the secrets embedded).
Nothing in them comes from real traffic, and `strip_pcapng_metadata.py` removes what the pcapng
headers record about the machine that captured them (hardware, OS, interface, capture filter).
