# Release Verification

Use these steps before installing ChangeGate in CI.

## Verify archive checksums

```bash
curl -fsSLO https://github.com/Gabriel0110/changegate/releases/download/vX.Y.Z/checksums.txt
curl -fsSLO https://github.com/Gabriel0110/changegate/releases/download/vX.Y.Z/changegate_X.Y.Z_linux_amd64.tar.gz
shasum -a 256 -c checksums.txt --ignore-missing
```

`scripts/install.sh` performs this check automatically and refuses to install when the checksum does not match.

## Verify signed checksums

```bash
curl -fsSLO https://github.com/Gabriel0110/changegate/releases/download/vX.Y.Z/checksums.txt.sig
curl -fsSLO https://github.com/Gabriel0110/changegate/releases/download/vX.Y.Z/checksums.txt.pem
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  checksums.txt
```

## Verify GitHub artifact attestations

```bash
gh attestation verify changegate_X.Y.Z_linux_amd64.tar.gz \
  --repo Gabriel0110/changegate
```

## Verify Docker image signature

```bash
cosign verify ghcr.io/Gabriel0110/changegate:vX.Y.Z
```

## Install a pinned version

```bash
export CHANGEGATE_VERSION=vX.Y.Z
curl -fsSL "https://raw.githubusercontent.com/Gabriel0110/changegate/${CHANGEGATE_VERSION}/scripts/install.sh" | bash
```

The GitHub Action wrapper also requires a pinned `version` input:

```yaml
- uses: Gabriel0110/changegate@vX.Y.Z
  with:
    version: vX.Y.Z
    plan: tfplan.json
```
