# Air-gap release transfer and installation

## Trust model

KCSP uses two separate trust decisions:

1. The connected release station verifies GitHub Actions keyless signatures,
   the signed release manifest, and all seven digest-pinned OCI references.
2. The station packages the exact image bytes, Helm chart, release evidence,
   and import tools, then signs the air-gap manifest with the university's
   transfer key.

Keep the transfer private key in an HSM or encrypted offline signing store. Its
public key and SHA-256 fingerprint must reach the isolated environment through
a separately controlled channel. A public key included only inside the bundle
is not a trust anchor.

## Connected release station

Provision the pinned Cosign and Helm images, Docker, `jq`, GNU tar, and the
university transfer keypair. Download the three signed release-manifest files,
then run:

```sh
export KCSP_AIRGAP_SIGNING_KEY_FILE=/secure/keys/kcsp-airgap.key
export KCSP_AIRGAP_PUBLIC_KEY_FILE=/secure/keys/kcsp-airgap.pub
export COSIGN_PASSWORD='<provided through the station secret manager>'
export KCSP_AIRGAP_OUTPUT_DIR=/secure/transfer

bash ops/supply-chain/build-airgap.sh \
  /secure/release/kcsp-release-manifest.json \
  /secure/release/kcsp-release-manifest.sigstore.json \
  /secure/release/kcsp-release-manifest.sha256
```

The builder verifies the public release before pulling anything. It rejects
mutable references, requires all five server components to share the platform
digest, exports three image archives (`platform`, `web`, and `dr`), packages the
Helm chart, signs the resulting manifest under an explicit no-Rekor/no-TSA
offline signing policy, embeds an empty-network trusted-root policy for key-based
verification, and creates a deterministic `.tar.gz` plus checksum.

Transfer the archive and checksum using approved removable media. Transfer the
trusted public key through a separate custody process. Record media serials,
SHA-256 values, operators, approvals, and custody timestamps.

## Isolated verification

The isolated verification host needs Docker, `jq`, GNU tar, `sha256sum`, and the
digest-pinned Cosign image preloaded through the approved toolchain bootstrap.
It does not need internet access.

```sh
sha256sum -c kcsp-airgap-0.1.0-linux-amd64.tar.gz.sha256
tar -xzf kcsp-airgap-0.1.0-linux-amd64.tar.gz

bash kcsp-airgap-0.1.0-linux-amd64/bin/verify-airgap.sh \
  ./kcsp-airgap-0.1.0-linux-amd64 \
  /media/trust/kcsp-airgap.pub
```

Cosign runs with Docker networking disabled. The verifier checks the out-of-band
public-key fingerprint, manifest signature, every artifact hash and size,
release-manifest binding, exact component set, digest-pinned source references,
and archive path safety. Any missing, extra-name, malformed, or modified
required artifact fails closed.

The verifier passes Cosign `--insecure-ignore-tlog` only for this institutional
key-based transfer signature because the explicit offline signing policy has no
public Rekor service. This does not skip signature, public-key, bundle, payload,
or artifact verification. Public release signatures are still checked against
GitHub OIDC and Rekor on the connected release station before packaging.

## Import into the private registry

Authenticate Docker to the internal registry using the site's secret manager.
Do not pass registry passwords to the import script.

```sh
bash kcsp-airgap-0.1.0-linux-amd64/bin/import-airgap.sh \
  ./kcsp-airgap-0.1.0-linux-amd64 \
  /media/trust/kcsp-airgap.pub \
  registry.soc.internal/kcsp \
  /secure/acceptance/airgap-import
```

The importer verifies the bundle again, validates each loaded image config
digest, pushes all seven component repositories, captures the digests returned
by the internal registry, and emits:

- `kcsp-airgap-images.values.yaml` for the six Helm-managed workloads;
- `kcsp-airgap-import-report.json`, including the separately operated DR image.

Render and review the chart with this values file plus the protected site values
before installation. The KCSP chart intentionally does not install single-node
PostgreSQL, ClickHouse, Kafka, MinIO, the OIDC provider, or the internal registry.
Those production dependencies and their own offline packages must be prepared
and accepted independently.
