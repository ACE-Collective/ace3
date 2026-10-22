#!/usr/bin/env bash
# Regenerates the pcap test fixtures. Run as root inside the dev container (needs tshark, dumpcap,
# curl, openssl and CAP_NET_RAW on loopback):
#   docker exec -u root <dev container> /opt/ace/tests/saq/modules/file_analysis/test_pcap/generate_fixtures.sh
# Everything captured is synthetic: loopback traffic to *.example names with a throwaway
# self-signed certificate, and hand-built frames from synthesize_frames.py.
set -euo pipefail

OUT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$WORK"' EXIT
PY=/venv/bin/python

openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=pcap-tls.example" \
    -addext "subjectAltName=DNS:pcap-tls12.example,DNS:pcap-tls13.example" \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>/dev/null

mkdir "$WORK/www"
printf 'plaintext payload carried over http\n' > "$WORK/www/payload.txt"
printf 'secret payload carried over tls 1.2\n' > "$WORK/www/secret12.txt"
printf 'secret payload carried over tls 1.3\n' > "$WORK/www/secret13.txt"

cat > "$WORK/serve.py" <<'EOF'
import functools, http.server, ssl, sys, threading
root, cert, key = sys.argv[1:4]
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=root)
def serve(port, version=None):
    server = http.server.HTTPServer(("127.0.0.1", port), handler)
    if version is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = version
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
serve(18080)
serve(18443, ssl.TLSVersion.TLSv1_2)
serve(18444, ssl.TLSVersion.TLSv1_3)
threading.Event().wait()
EOF
"$PY" "$WORK/serve.py" "$WORK/www" "$WORK/cert.pem" "$WORK/key.pem" &
sleep 1

dumpcap -q -i lo -f "tcp port 18080 or tcp port 18443 or tcp port 18444" -w "$WORK/live.pcapng" &
DUMPCAP=$!
sleep 2

CURL=(curl -s -o /dev/null --http1.1 -k -A "pcap-fixture-agent/1.0")
"${CURL[@]}" "http://pcap-http.example:18080/payload.txt" --resolve pcap-http.example:18080:127.0.0.1
SSLKEYLOGFILE="$WORK/sslkeylog.txt" "${CURL[@]}" --tlsv1.2 --tls-max 1.2 \
    "https://pcap-tls12.example:18443/secret12.txt" --resolve pcap-tls12.example:18443:127.0.0.1
SSLKEYLOGFILE="$WORK/sslkeylog.txt" "${CURL[@]}" --tlsv1.3 \
    "https://pcap-tls13.example:18444/secret13.txt" --resolve pcap-tls13.example:18444:127.0.0.1
sleep 2
kill -INT "$DUMPCAP"
wait "$DUMPCAP" || true

"$PY" "$OUT/synthesize_frames.py" "$OUT/network.pcap"
# drop what the pcapng headers record about this machine (hardware, OS, interface, capture filter)
"$PY" "$OUT/strip_pcapng_metadata.py" "$WORK/live.pcapng" "$OUT/http_tls.pcapng"
cp "$WORK/sslkeylog.txt" "$OUT/sslkeylog.txt"
editcap --inject-secrets "tls,$WORK/sslkeylog.txt" "$WORK/live.pcapng" "$WORK/dsb.pcapng"
"$PY" "$OUT/strip_pcapng_metadata.py" "$WORK/dsb.pcapng" "$OUT/http_tls_dsb.pcapng"
chmod 644 "$OUT"/*.pcap "$OUT"/*.pcapng "$OUT/sslkeylog.txt"
chown --reference="$OUT" "$OUT"/*.pcap "$OUT"/*.pcapng "$OUT/sslkeylog.txt"
ls -l "$OUT"
