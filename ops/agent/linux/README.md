# KCSP Linux Agent

This package runs the KCSP lightweight agent as a locked-down systemd service.
It reads journald through the `systemd-journal` group, persists its cursor only
after the event reaches the encrypted transport queue, and forwards batches to
the KCSP ingestion gateway over HTTPS or mTLS.

## Supported host baseline

- Linux amd64 or arm64
- systemd 247 or newer with persistent journald
- GNU coreutils, OpenSSL and tar
- outbound HTTPS access to the KCSP gateway
- a one-time KCSP agent enrollment token

## Build a signed package

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath -ldflags='-s -w' -o ./dist/kcsp-agent ./cmd/agent

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out /secure/offline/kcsp-agent-release.key
openssl pkey -in /secure/offline/kcsp-agent-release.key -pubout \
  -out ./dist/kcsp-agent-release.pub

./ops/agent/linux/build-package.sh \
  --binary ./dist/kcsp-agent \
  --version 0.5.0 \
  --arch amd64 \
  --output-dir ./dist \
  --signing-key /secure/offline/kcsp-agent-release.key
```

Keep the release private key offline. Distribute the public key through a
separate trusted configuration-management channel.

## Install

Extract the package, create a host-specific config from `agent.env.example`,
then install with the trusted release public key:

```bash
sudo ./install.sh \
  --config /root/kcsp-agent.env \
  --public-key /etc/kcsp-trust/kcsp-agent-release.pub
```

The installer rejects modified payloads, unsigned packages, symlinks, malformed
or duplicate config keys, plaintext gateway URLs and missing enrollment data.
`--allow-unsigned` and `--allow-insecure-http` are explicit development-only
break-glass options and must not be used in production.

After the first successful enrollment, remove the one-time enrollment token
from `/etc/kcsp/agent.env`. The rotated credential remains under
`/var/lib/kcsp-agent` with mode 0600.

## Operations

```bash
systemctl status kcsp-agent.service
journalctl -u kcsp-agent.service --since today
sudo ./uninstall.sh
```

The default uninstall keeps the queue, cursor, identity, credential and config
for a safe reinstall. Use `--purge` only after the endpoint is decommissioned
and its agent credential is revoked in KCSP.

Run `self-test.sh --binary PATH` before publishing a package. It validates shell
syntax, critical systemd hardening, archive checksums, signature verification
and byte-for-byte binary integrity without installing a host service.
