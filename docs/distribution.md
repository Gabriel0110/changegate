# Install Options

ChangeGate is distributed as a single CLI binary, release archives, Linux packages, Docker images, and an npm installer package.

## Docker

Use the official image from GitHub Container Registry when ChangeGate runs inside CI, containerized build workers, or local Docker workflows:

```bash
docker run --rm ghcr.io/gabriel0110/changegate:vX.Y.Z version
docker run --rm -v "$PWD:/work:ro" ghcr.io/gabriel0110/changegate:vX.Y.Z scan --plan /work/tfplan.json
```

Published tags:

- `vX.Y.Z`
- `X.Y.Z`
- `X.Y`
- `X`
- `latest`

Images are multi-architecture for `linux/amd64` and `linux/arm64`, run as a numeric non-root user, include OCI version/revision labels, and are signed.

When the image is used as the job image in GitLab CI with `entrypoint: [""]`, call the binary at `/changegate`:

```yaml
changegate:
  image:
    name: ghcr.io/gabriel0110/changegate:vX.Y.Z
    entrypoint: [""]
  script:
    - /changegate version
    - /changegate --no-color scan --plan tfplan.json
```

## npm

Use the npm package when Node.js/npm is already available on developer workstations or CI runners:

```bash
npx changegate version
npx changegate scan --plan tfplan.json
```

The installer supports macOS, Linux, and Windows on `amd64`/`arm64`. It downloads the release archive and `checksums.txt`, verifies the signed checksum manifest with `cosign`, verifies the archive SHA-256 checksum, and installs a local CLI shim named `changegate`.

Set `CHANGEGATE_VERSION` when you need a specific ChangeGate release:

```bash
CHANGEGATE_VERSION=vX.Y.Z npx changegate version
```

Advanced install environments can use `CHANGEGATE_RELEASE_BASE_URL` to point the installer at an internal artifact mirror that serves the same release archive names, checksum manifest, and Sigstore signature artifacts.
