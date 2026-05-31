#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
if [[ -z "${version}" ]]; then
  echo "usage: scripts/release-build.sh vX.Y.Z" >&2
  exit 2
fi
if [[ "${version}" != v* ]]; then
  echo "release version must start with v, got ${version}" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist="${root}/dist"
commit="${GITHUB_SHA:-$(git -C "${root}" rev-parse --verify HEAD 2>/dev/null || echo unknown)}"
date="${SOURCE_DATE_EPOCH:-}"
if [[ -n "${date}" ]]; then
  build_date="$(date -u -r "${date}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d "@${date}" '+%Y-%m-%dT%H:%M:%SZ')"
else
  build_date="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
fi

rm -rf "${dist}"
mkdir -p "${dist}"

ldflags=(
  "-s"
  "-w"
  "-X github.com/Gabriel0110/changegate/internal/buildinfo.Version=${version}"
  "-X github.com/Gabriel0110/changegate/internal/buildinfo.Commit=${commit}"
  "-X github.com/Gabriel0110/changegate/internal/buildinfo.Date=${build_date}"
)

targets=(
  "linux amd64 tar.gz"
  "linux arm64 tar.gz"
  "darwin amd64 tar.gz"
  "darwin arm64 tar.gz"
  "windows amd64 zip"
  "windows arm64 zip"
)

for target in "${targets[@]}"; do
  read -r goos goarch archive_type <<<"${target}"
  name="changegate_${version#v}_${goos}_${goarch}"
  work="${dist}/${name}"
  mkdir -p "${work}"
  binary="changegate"
  if [[ "${goos}" == "windows" ]]; then
    binary="changegate.exe"
  fi
  echo "building ${goos}/${goarch}"
  (
    cd "${root}"
    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" go build \
      -trimpath \
      -ldflags="${ldflags[*]}" \
      -o "${work}/${binary}" \
      ./cmd/changegate
  )
  cp "${root}/README.md" "${work}/README.md"
  cp "${root}/LICENSE" "${work}/LICENSE" 2>/dev/null || true
  if [[ "${archive_type}" == "zip" ]]; then
    (cd "${dist}" && COPYFILE_DISABLE=1 zip -Xqr "${name}.zip" "${name}")
  else
    COPYFILE_DISABLE=1 tar --no-xattrs -C "${dist}" -czf "${dist}/${name}.tar.gz" "${name}"
  fi
  rm -rf "${work}"
done

(
  cd "${dist}"
  for artifact in *.tar.gz *.zip; do
    [[ -f "${artifact}" ]] || continue
    shasum -a 256 "${artifact}"
  done | LC_ALL=C sort -k2 > checksums.txt
)

if [[ "${CHANGEGATE_SKIP_SBOM:-0}" != "1" ]]; then
  command -v syft >/dev/null 2>&1 || {
    echo "syft is required to generate release SBOMs; set CHANGEGATE_SKIP_SBOM=1 only for local dry runs" >&2
    exit 1
  }
  for artifact in "${dist}"/*.tar.gz "${dist}"/*.zip; do
    syft "file:${artifact}" -o cyclonedx-json > "${artifact}.sbom.cdx.json"
  done
fi

if [[ "${CHANGEGATE_SKIP_SIGN:-0}" != "1" ]]; then
  command -v cosign >/dev/null 2>&1 || {
    echo "cosign is required to sign release checksums; set CHANGEGATE_SKIP_SIGN=1 only for local dry runs" >&2
    exit 1
  }
  COSIGN_YES=true cosign sign-blob \
    --output-signature "${dist}/checksums.txt.sig" \
    --output-certificate "${dist}/checksums.txt.pem" \
    "${dist}/checksums.txt"
fi

echo "release artifacts written to ${dist}"
