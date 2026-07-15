#!/usr/bin/env bash
# Generates an ephemeral development CA and starts PostgreSQL with TLS enabled.
set -euo pipefail

umask 077

readonly TLS_DIRECTORY="/var/lib/postgresql/cigar-development-tls"
readonly CA_CERTIFICATE="$TLS_DIRECTORY/ca.crt"
readonly SERVER_CERTIFICATE="$TLS_DIRECTORY/server.crt"
readonly SERVER_PRIVATE_KEY="$TLS_DIRECTORY/server.key"

install -d -m 0700 -o postgres -g postgres "$TLS_DIRECTORY"

if [[ ! -s "$CA_CERTIFICATE" || ! -s "$SERVER_CERTIFICATE" || ! -s "$SERVER_PRIVATE_KEY" ]]; then
  rm -f "$TLS_DIRECTORY"/*
  openssl genrsa -out "$TLS_DIRECTORY/ca.key" 3072 >/dev/null 2>&1
  openssl req -x509 -new -sha256 \
    -key "$TLS_DIRECTORY/ca.key" \
    -out "$CA_CERTIFICATE" \
    -days 2 \
    -subj "/CN=CIGAR Development PostgreSQL CA" >/dev/null 2>&1
  openssl genrsa -out "$SERVER_PRIVATE_KEY" 3072 >/dev/null 2>&1
  openssl req -new -sha256 \
    -key "$SERVER_PRIVATE_KEY" \
    -out "$TLS_DIRECTORY/server.csr" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -addext "keyUsage=digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
  openssl x509 -req -sha256 \
    -in "$TLS_DIRECTORY/server.csr" \
    -CA "$CA_CERTIFICATE" \
    -CAkey "$TLS_DIRECTORY/ca.key" \
    -CAcreateserial \
    -copy_extensions copy \
    -out "$SERVER_CERTIFICATE" \
    -days 2 >/dev/null 2>&1
  rm -f "$TLS_DIRECTORY/ca.key" "$TLS_DIRECTORY/ca.srl" "$TLS_DIRECTORY/server.csr"
fi

chown postgres:postgres "$CA_CERTIFICATE" "$SERVER_CERTIFICATE" "$SERVER_PRIVATE_KEY"
chmod 0600 "$CA_CERTIFICATE" "$SERVER_CERTIFICATE" "$SERVER_PRIVATE_KEY"

# The upstream entrypoint creates the PostgreSQL 18 major-version parent directory. Its
# ownership logic expects the image default umask; private TLS material is already sealed above.
umask 022
exec docker-entrypoint.sh "$@" \
  -c ssl=on \
  -c "ssl_ca_file=$CA_CERTIFICATE" \
  -c "ssl_cert_file=$SERVER_CERTIFICATE" \
  -c "ssl_key_file=$SERVER_PRIVATE_KEY"
