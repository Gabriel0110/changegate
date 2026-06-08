#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmpdir}"
  rm -rf "${root}/npm/changegate/vendor"
}
trap cleanup EXIT

cd "${root}"
rm -rf "${root}/npm/changegate/vendor"

go build -o "${tmpdir}/changegate" ./cmd/changegate

cd "${root}/npm/changegate"
npm test
npm pack --dry-run
package_file="$(npm pack --pack-destination "${tmpdir}" | tail -n 1)"

cd "${tmpdir}"
npm init -y >/dev/null
CHANGEGATE_INSTALL_BINARY="${tmpdir}/changegate" npm install "${tmpdir}/${package_file}" >/dev/null
npx changegate version
npx changegate --help >/dev/null
