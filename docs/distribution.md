# Distribution

ChangeGate publishes release archives, Linux packages, Docker images, and an npm installer package from the GitHub release workflow.

## Docker

The official image is published to GitHub Container Registry:

```bash
docker run --rm ghcr.io/gabriel0110/changegate:v0.3.0 version
docker run --rm -v "$PWD:/work:ro" ghcr.io/gabriel0110/changegate:v0.3.0 scan --plan /work/tfplan.json
```

Published tags:

- `vX.Y.Z`
- `X.Y.Z`
- `X.Y`
- `X`
- `latest`

Images are multi-architecture for `linux/amd64` and `linux/arm64`, run as a numeric non-root user, include OCI version/revision labels, and are signed by the release workflow.

## npm

The `changegate` npm package installs a platform-specific ChangeGate binary from GitHub Releases:

```bash
npx changegate version
npx changegate scan --plan tfplan.json
```

The installer supports macOS, Linux, and Windows on `amd64`/`arm64`. It downloads the release archive and `checksums.txt`, verifies the archive SHA-256 checksum, and installs a local CLI shim named `changegate`.

## Release Workflow

Normal pull request CI does not require Docker registry or npm publishing secrets. It validates:

- Docker image build and runtime smoke tests.
- npm package unit tests, package dry-run, and local install through a locally built ChangeGate binary.

Release publishing is triggered by pushing a `vX.Y.Z` tag.

Required for Docker publishing:

- The repository `GITHUB_TOKEN` with `packages: write`.

Required for npm publishing:

- `NPM_TOKEN` repository secret with permission to publish the `changegate` npm package.

Optional:

- `HOMEBREW_TAP_REPOSITORY` repository variable and `HOMEBREW_TAP_TOKEN` repository secret for Homebrew tap publishing.

If the npm or Homebrew secrets are not configured, the release workflow skips those publishing steps without failing the release.
