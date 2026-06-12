#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
if [[ -z "${version}" ]]; then
  echo "usage: scripts/release-notes.sh vX.Y.Z" >&2
  exit 2
fi

previous="$(git describe --tags --abbrev=0 "${version}^" 2>/dev/null || true)"
range=""
if [[ -n "${previous}" ]]; then
  range="${previous}..${version}"
fi

cat <<NOTES
## ChangeGate ${version}

### Highlights

$(if [[ -n "${range}" ]]; then git log --format='- %s' "${range}"; else echo "- Initial release."; fi)

### Breaking changes

- None declared.

### Verification

Verify the downloaded archive and checksum manifest:

\`\`\`bash
artifact="changegate_${version#v}_linux_amd64.tar.gz"
grep "  \${artifact}$" checksums.txt | shasum -a 256 -c -
cosign verify-blob \\
  --bundle checksums.txt.sigstore.json \\
  --certificate-identity "https://github.com/Gabriel0110/changegate/.github/workflows/release.yml@refs/tags/${version}" \\
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \\
  checksums.txt
\`\`\`

### Supply chain evidence

This release includes SHA-256 checksums, signed checksums, CycloneDX SBOMs, GitHub artifact attestations, a signed Docker image, and Linux `.deb`, `.rpm`, and `.apk` packages.
NOTES
