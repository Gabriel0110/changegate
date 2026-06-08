# ChangeGate npm package

This package installs the ChangeGate CLI for local development and CI jobs that already have Node.js/npm available.

```bash
npx changegate version
npx changegate scan --plan tfplan.json
```

During installation, the package downloads the matching ChangeGate release archive from GitHub Releases, verifies it against the published `checksums.txt`, and installs a local CLI shim named `changegate`.

## Supported Platforms

- macOS arm64 and amd64
- Linux arm64 and amd64
- Windows arm64 and amd64

Unsupported operating systems or CPU architectures fail during install with a clear error.

## Environment Variables

Most users do not need these. They exist for CI validation and controlled mirrors.

| Variable | Purpose |
| --- | --- |
| `CHANGEGATE_VERSION` | Override the ChangeGate version to install. |
| `CHANGEGATE_RELEASE_TAG` | Override the GitHub release tag. |
| `CHANGEGATE_RELEASE_BASE_URL` | Download artifacts from a mirror instead of GitHub Releases. |
| `CHANGEGATE_INSTALL_BINARY` | Copy an already-built local binary instead of downloading artifacts. |
| `CHANGEGATE_NPM_SKIP_INSTALL` | Skip binary installation. Useful only for package metadata inspection. |

## Security

The installer does not use runtime npm dependencies. It fetches only ChangeGate release artifacts and verifies the selected archive checksum before extracting it.
