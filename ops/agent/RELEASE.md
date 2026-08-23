# KCSP Endpoint Agent Release

Tagged releases publish three endpoint packages:

- Linux amd64 tar.gz
- Linux arm64 tar.gz
- Windows amd64 zip

The release environment must provide these base64-encoded GitHub secrets:

- `KCSP_AGENT_SIGNING_KEY_B64`: offline-managed RSA private release key
- `KCSP_AGENT_SIGNING_PUBLIC_KEY_B64`: matching trusted public key

`ops/agent/build-release.sh` rejects mismatched keys and creates a signed
`kcsp-agent-release-manifest.sha256`. Linux packages also carry a detached
signature for their internal payload manifest. CI generates an ephemeral key,
builds every target, validates Windows and Linux deployment contracts, and
proves that a modified release package is rejected.

The public key asset attached to GitHub is a convenience copy, not a trust
bootstrap mechanism. Distribute and pin the public key fingerprint through the
university configuration-management or offline media trust channel.
