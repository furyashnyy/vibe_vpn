#!/usr/bin/env bash
set -Eeuo pipefail
# Generates a unique private CA and a CA-signed TLS 1.3 server certificate.
# The CA stays local; copy ONLY ca.pem to the connecting peer.
NAME="${1:?usage: make-certs.sh dns-name destination-directory}"
DEST="${2:?destination directory required}"
if ! [[ "$NAME" =~ ^[a-zA-Z0-9.-]+$ ]]; then echo "invalid DNS name" >&2; exit 1; fi
mkdir -p "$DEST"
chmod 700 "$DEST"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc \
  -days 365 -sha256 -keyout "$DEST/ca.key" -out "$DEST/ca.pem" \
  -subj '/CN=Rustine Private CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc \
  -sha256 -keyout "$DEST/key.pem" -out "$DEST/server.csr" \
  -subj "/CN=$NAME" >/dev/null 2>&1
cat > "$DEST/server.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$NAME
EXT
openssl x509 -req -in "$DEST/server.csr" -CA "$DEST/ca.pem" -CAkey "$DEST/ca.key" \
  -CAcreateserial -out "$DEST/cert.pem" -days 365 -sha256 \
  -extfile "$DEST/server.ext" >/dev/null 2>&1
rm -f "$DEST/server.csr" "$DEST/server.ext" "$DEST/ca.srl"
chmod 600 "$DEST/ca.key" "$DEST/key.pem"
chmod 644 "$DEST/ca.pem" "$DEST/cert.pem"
printf 'Created TLS identity for %s in %s\n' "$NAME" "$DEST"
