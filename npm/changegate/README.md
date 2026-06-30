# ChangeGate npm package

This package installs the ChangeGate CLI for local development and CI jobs that already have Node.js/npm available.

```bash
npx changegate version
npx changegate scan --plan tfplan.json
```

During installation, the package downloads the matching ChangeGate release archive from GitHub Releases, verifies the signed checksum manifest with `cosign`, verifies the archive checksum, and installs a local CLI shim named `changegate`.

When installing from a source checkout instead of the published npm package, set `CHANGEGATE_VERSION` to the release you want to download or set `CHANGEGATE_INSTALL_BINARY` to an already-built local binary.

## Supported Platforms

- macOS arm64 and amd64
- Linux arm64 and amd64
- Windows arm64 and amd64

Unsupported operating systems or CPU architectures fail during install with a clear error.

## Environment Variables

Most installs work without configuration. These variables are available for pinned versions, artifact mirrors, and controlled build environments.

| Variable | Purpose |
| --- | --- |
| `CHANGEGATE_VERSION` | Override the ChangeGate version to install. |
| `CHANGEGATE_RELEASE_TAG` | Override the GitHub release tag. |
| `CHANGEGATE_RELEASE_BASE_URL` | Download artifacts from a mirror instead of GitHub Releases. |
| `CHANGEGATE_INSTALL_BINARY` | Copy an already-built local binary instead of downloading artifacts. |
| `CHANGEGATE_NPM_SKIP_INSTALL` | Skip binary installation when a packaging environment needs to avoid network access. |
| `CHANGEGATE_NPM_VERIFY_SIG` | Set to `false` only in trusted test environments where signature verification is intentionally unavailable. |

## Security

The installer does not use runtime npm dependencies. It fetches only ChangeGate release artifacts, verifies the signed checksum manifest before trusting `checksums.txt`, and verifies the selected archive checksum before extracting it.
