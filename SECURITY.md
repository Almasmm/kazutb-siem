# Security policy

## Reporting a vulnerability

Use GitHub Private Vulnerability Reporting for this repository. Do not disclose
suspected vulnerabilities in a public issue, discussion, pull request, log, or
chat channel.

Include:

- affected commit, version, or image digest;
- reproducible steps with sensitive values removed;
- security impact and required preconditions;
- relevant logs or packet captures after redaction;
- a safe contact method for coordinated follow-up.

Do not access university data, disrupt services, weaken retention, or perform
destructive testing while validating a report.

## Supported artifacts

Until the first stable release, security fixes are applied to the current
`main` branch and the newest signed release. Older prototypes are unsupported.

Release images are identified by digest. A tag alone is not sufficient
evidence of artifact identity.

## Release integrity

The release workflow:

- builds from the tagged Git revision;
- publishes immutable architecture-specific OCI images;
- attaches BuildKit SBOM and maximum-mode provenance attestations;
- signs each image digest through GitHub Actions OIDC and Sigstore;
- signs a manifest that binds the version and Git revision to all image
  digests;
- never publishes a mutable `latest` tag.

Operators must verify the image signatures, signed manifest, and checksum
before updating Helm values. Verification does not replace vulnerability
assessment, change approval, backup validation, or runtime monitoring.

## Secrets

Never commit credentials, tokens, private keys, production URLs containing
credentials, evidence, or real telemetry. Rotate any value that reaches Git,
CI output, issue attachments, or an unapproved system, even if it is later
deleted.
