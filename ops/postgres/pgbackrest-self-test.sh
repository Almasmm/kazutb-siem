#!/bin/sh
set -eu

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

export KCSP_PITR_ENABLED=true
export PGBACKREST_REPO1_S3_KEY=self-test-access
export PGBACKREST_REPO1_S3_KEY_SECRET=self-test-secret-key
export PGBACKREST_REPO1_CIPHER_PASS=self-test-repository-cipher-passphrase
export KCSP_PITR_S3_ENDPOINT=pitr.example.invalid
export KCSP_PITR_S3_PORT=443
export KCSP_PITR_S3_BUCKET=kcsp-pitr-test
export KCSP_PITR_TLS_VERIFY=y
export KCSP_PITR_STATE_PATH="$root/state"
export PGBACKREST_CONFIG="$root/config/pgbackrest.conf"
export PGDATA="$root/postgres"

/usr/local/bin/kcsp-configure-pgbackrest
test -s "$PGBACKREST_CONFIG"
grep -q 'repo1-cipher-type=aes-256-cbc' "$PGBACKREST_CONFIG"
grep -q 'repo1-storage-verify-tls=y' "$PGBACKREST_CONFIG"
if grep -q "$PGBACKREST_REPO1_S3_KEY_SECRET" "$PGBACKREST_CONFIG"; then
    echo "pgBackRest configuration leaked a secret" >&2
    exit 1
fi
if grep -q "$PGBACKREST_REPO1_CIPHER_PASS" "$PGBACKREST_CONFIG"; then
    echo "pgBackRest configuration leaked the cipher passphrase" >&2
    exit 1
fi

echo '{"status":"ok","test":"kcsp-pgbackrest-self-test"}'
