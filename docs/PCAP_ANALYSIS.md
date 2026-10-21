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
 ├─ PCAP DNS               pcap_dns             names queried and answered; FQDNs and answer IPs
 ├─ PCAP TLS               pcap_tls             sessions (SNI, JA4, certificates); FQDNs, JA4, certificate files
 ├─ PCAP HTTP              pcap_http            requests; URLs, Host FQDNs, User-Agents
 ├─ PCAP Files             pcap_files           files carved from HTTP, SMB, FTP-data, TFTP and IMF
 └─ PCAP TLS Decryption    pcap_tls_decryption  only what the decrypted traffic adds beyond the above
sslkeylog.txt
 └─ TLS Key Log            tls_keylog           secret counts by label (never the secrets); tag tls_keylog
```

- IP addresses, MAC addresses and hostnames are added `volatile`, so they are hidden unless the
  analyst selects "Show All Observables" or they lead to a detection. Everything else is visible.
- Within a node, observables sort by type (files, URLs, FQDNs, JA4, User-Agents, hostnames, IPs, MACs).
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
and runs tshark twice in the Landlock sandbox:

1. `-q -z io,stat,0 -z endpoints,... -z conv,...` for the packet count, the endpoints and the flows;
2. `-T json -Y <filter> -e <fields> --export-objects ...` for DNS, TLS handshakes, HTTP(/2) headers,
   DHCP and NBNS, plus the exported objects. Certificates are taken from the handshake bytes.

The result is the capture *index*, kept in `PcapAnalysis.details`. The category instances
(`pcap_dns`, `pcap_tls`, `pcap_http`, `pcap_files`: one class, `PcapCategoryAnalyzer`, configured
once per `category`) wait for it and read it; they never run tshark.

tshark's dissectors parse hostile bytes, so tshark only ever runs through
`saq/sandbox/runner.py`: a private working directory (holding a copy of the capture, never a
link, so tshark cannot change the evidence), nothing
of ACE readable, no network (`sandbox.allowed_tcp_ports` stays empty), rlimits, a `tshark_timeout`
and an output cap. On a node without Landlock the module refuses to run tshark and records an
error rather than running it unsandboxed. Every failure (no Landlock, a timeout, too much output, a
corrupt capture) is recorded in the analysis `error`, shown in its summary, and logged at ERROR
with an error report through `log_loop_exception`. A capture cut short mid-packet is dissected as
far as it goes.

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
  it and decrypts that capture again with every key log in the tree, adding to the existing node.
  Applying the same key logs twice adds nothing.
- **Embedded secrets.** A pcapng with a Decryption Secrets Block (`editcap --inject-secrets`) is
  decrypted by tshark on its own, so its first pass already sees inside TLS.

## Limits

- HTTP/2 (most decrypted HTTPS): request URLs come from the `:authority`/`:path` headers, but tshark
  4.4 cannot export HTTP/2 bodies, so no files are carved from it.
- JA4 is the only fingerprint added (tshark computes it). JA3/JA3S are not added; the rest of the
  JA4+ family is under the FoxIO license and not implemented.
- `archive` does not extract pcaps from archives (`excluded_mime_types` lists
  `application/vnd.tcpdump.pcap`); a capture inside a zip is not dissected.
- No analysis caching (`cache_ttl` unset): `tls_keylog` changes another observable's analysis,
  which the cache cannot replay.

## Configuration

Every pcap module takes the same optional settings (`PcapModuleConfig`), set on
`analysis_module_pcap_analyzer` in `etc/saq.default.yaml`: `tshark_path`, `tshark_timeout`,
`work_dir`, `sandbox`, `max_file_size`, `max_keylog_size`, `max_table_rows`,
`max_extracted_files`, `max_observables_per_type`, `excluded_fqdn_suffixes`. The category instances
also take `category`. The modules are in the `file` module group.

The `tshark` package is installed in the image (`Dockerfile`).

## Test fixtures

`tests/saq/modules/file_analysis/test_pcap/generate_fixtures.sh` regenerates every fixture inside the
dev container: `network.pcap` (hand-built DHCP/NBNS/DNS frames from `synthesize_frames.py`),
`http_tls.pcapng` (a loopback capture of plain HTTP plus TLS 1.2 and TLS 1.3 requests to `*.example`
names), its `sslkeylog.txt`, and `http_tls_dsb.pcapng` (the same capture with the secrets embedded).
Nothing in them comes from real traffic, and `strip_pcapng_metadata.py` removes what the pcapng
headers record about the machine that captured them (hardware, OS, interface, capture filter).
