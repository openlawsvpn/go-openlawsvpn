#!/bin/bash
# gencerts.sh — generate self-signed CA + server cert + DH params for mock server.
# Run once during Docker build; output lands in /etc/mock-vpn/.
set -euo pipefail

OUT=/etc/mock-vpn
mkdir -p "$OUT"

# 1. CA key + self-signed cert (10-year)
openssl genrsa -out "$OUT/ca.key" 2048
openssl req -new -x509 -days 3650 -key "$OUT/ca.key" -out "$OUT/ca.crt" \
  -subj "/CN=mock-ca/O=openlawsvpn-test"

# 2. Server key + CSR + cert signed by CA
openssl genrsa -out "$OUT/server.key" 2048
openssl req -new -key "$OUT/server.key" -out "$OUT/server.csr" \
  -subj "/CN=mock-server/O=openlawsvpn-test"
openssl x509 -req -days 3650 -in "$OUT/server.csr" \
  -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -out "$OUT/server.crt"

# 3. Client key + cert (used by Go integration tests)
openssl genrsa -out "$OUT/client.key" 2048
openssl req -new -key "$OUT/client.key" -out "$OUT/client.csr" \
  -subj "/CN=mock-client/O=openlawsvpn-test"
openssl x509 -req -days 3650 -in "$OUT/client.csr" \
  -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -out "$OUT/client.crt"

# 4. DH params (pre-generated 2048-bit to avoid slow runtime generation)
openssl dhparam -out "$OUT/dh.pem" 2048

echo "Certificates written to $OUT"
ls -la "$OUT"
