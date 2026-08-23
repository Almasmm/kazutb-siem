# Release and supply-chain runbook

## Objective

Produce traceable KCSP application images whose source revision, SBOM,
provenance, signatures, and release manifest can be independently verified
before deployment.

## Release artifacts

A semantic version tag produces six image references:

- `kcsp-api`
- `kcsp-processor`
- `kcsp-soar-worker`
- `kcsp-ai-worker`
- `kcsp-web`
- `kcsp-dr`

The four application server images share one intentionally identical platform
image and select their process through the Kubernetes command. Each repository
is signed separately because OCI signatures are repository-scoped.

Every release also contains:

- `kcsp-release-manifest.json`
- `kcsp-release-manifest.sha256`
- `kcsp-release-manifest.sigstore.json`

The manifest binds all image digests to one version and full Git commit SHA.

## GitHub controls

Configure the `release` environment before creating a tag:

- require designated reviewer approval;
- restrict deployment branches and tags;
- protect semantic version tags from deletion or retargeting;
- require the normal CI, Helm, and supply-chain checks on `main`;
- restrict workflow changes with CODEOWNERS review;
- enable GitHub Private Vulnerability Reporting.

The workflow requires only the repository `GITHUB_TOKEN` and GitHub OIDC. Do
not add a long-lived Cosign private key.

## Create a release

1. Confirm `main` is green and the worktree is clean.
2. Review migration and rollback compatibility.
3. Confirm current backup and restore evidence.
4. Create and push an annotated semantic version tag:

```sh
git tag -s v0.1.0 -m "KCSP v0.1.0"
git push origin v0.1.0
```

The `release.yml` workflow validates the version, builds only
`linux/amd64`, attaches BuildKit SBOM and provenance, signs image digests,
signs the release manifest, and publishes GitHub Release assets. No `latest`
tag is created.

## Verify before deployment

Download all three manifest files into one directory. Run:

```sh
bash ops/supply-chain/verify-release.sh \
  ./kcsp-release-manifest.json \
  ./kcsp-release-manifest.sigstore.json \
  ./kcsp-release-manifest.sha256
```

The verifier requires Docker, `jq`, and `sha256sum`. It uses the digest-pinned
Cosign image and requires:

- issuer `https://token.actions.githubusercontent.com`;
- certificate identity matching this repository's `release.yml`;
- six digest-pinned images;
- a valid signed manifest bundle;
- a matching local checksum.

After verification, copy the exact image digests from the manifest into the
protected Helm values file. Do not deploy the semantic tag directly.

## Promotion

Promote one verified digest through development, staging, and production.
Frontend OIDC, API base path, tenant, and timezone are injected through public
runtime `config.js`, so environment promotion does not rebuild or mutate the
web image.

## Failure handling

- If a build fails, fix the source and create a new version. Do not retarget a
  published tag.
- If signing fails, do not deploy unsigned images and do not bypass OIDC
  identity checks.
- If a vulnerability is found after release, preserve evidence, revoke the
  deployment through change control, patch `main`, and publish a new version.
- If registry content differs from the signed digest, stop the deployment and
  treat it as a supply-chain incident.

Store the workflow URL, release manifest, verification output, Helm render,
approvals, and post-deployment checks in the university change record.
