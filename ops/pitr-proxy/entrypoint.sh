#!/bin/sh
set -eu

umask 077
certificate_dir=/run/kcsp-pitr
mkdir -p "$certificate_dir" /tmp/client_body /tmp/proxy

openssl req \
    -x509 \
    -newkey rsa:3072 \
    -sha256 \
    -nodes \
    -days 7 \
    -subj /CN=pitr-s3-proxy \
    -addext subjectAltName=DNS:pitr-s3-proxy,DNS:localhost,IP:127.0.0.1 \
    -keyout "$certificate_dir/private.key" \
    -out "$certificate_dir/public.crt" \
    >/dev/null 2>&1

chmod 0600 "$certificate_dir/private.key"
chmod 0644 "$certificate_dir/public.crt"
exec nginx -g 'daemon off;'
