#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
checksums="${2:-}"
out="${3:-}"
if [[ -z "${version}" || -z "${checksums}" || -z "${out}" ]]; then
  echo "usage: scripts/homebrew-formula.sh vX.Y.Z dist/checksums.txt output.rb" >&2
  exit 2
fi

plain="${version#v}"
checksum_for() {
  local artifact="$1"
  awk -v file="${artifact}" '$2 == file { print $1 }' "${checksums}"
}

linux_amd64="$(checksum_for "changegate_${plain}_linux_amd64.tar.gz")"
linux_arm64="$(checksum_for "changegate_${plain}_linux_arm64.tar.gz")"
darwin_amd64="$(checksum_for "changegate_${plain}_darwin_amd64.tar.gz")"
darwin_arm64="$(checksum_for "changegate_${plain}_darwin_arm64.tar.gz")"

for value in "${linux_amd64}" "${linux_arm64}" "${darwin_amd64}" "${darwin_arm64}"; do
  if [[ -z "${value}" ]]; then
    echo "missing checksum needed for Homebrew formula" >&2
    exit 1
  fi
done

sed \
  -e "s/X.Y.Z/${plain}/g" \
  -e "s/LINUX_AMD64_SHA256/${linux_amd64}/g" \
  -e "s/LINUX_ARM64_SHA256/${linux_arm64}/g" \
  -e "s/DARWIN_AMD64_SHA256/${darwin_amd64}/g" \
  -e "s/DARWIN_ARM64_SHA256/${darwin_arm64}/g" \
  packaging/homebrew/changegate.rb > "${out}"
