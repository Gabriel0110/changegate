#!/usr/bin/env bash
set -euo pipefail

version="${CHANGEGATE_VERSION:-${1:-}}"
repo="${CHANGEGATE_REPO:-Gabriel0110/changegate}"
install_dir="${CHANGEGATE_INSTALL_DIR:-/usr/local/bin}"

if [[ -z "${version}" ]]; then
  echo "usage: CHANGEGATE_VERSION=vX.Y.Z scripts/install.sh" >&2
  echo "refusing to install an unpinned version" >&2
  exit 2
fi
if [[ "${version}" != v* ]]; then
  echo "CHANGEGATE_VERSION must start with v, got ${version}" >&2
  exit 2
fi

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "${os}" in
  linux|darwin) ;;
  *) echo "unsupported OS: ${os}" >&2; exit 2 ;;
esac
case "${arch}" in
  x86_64|amd64) arch="amd64" ;;
  arm64|aarch64) arch="arm64" ;;
  *) echo "unsupported architecture: ${arch}" >&2; exit 2 ;;
esac

base="https://github.com/${repo}/releases/download/${version}"
name="changegate_${version#v}_${os}_${arch}"
archive="${name}.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

curl -fsSL "${base}/${archive}" -o "${tmp}/${archive}"
curl -fsSL "${base}/checksums.txt" -o "${tmp}/checksums.txt"

expected="$(awk -v file="${archive}" '$2 == file { print $1 }' "${tmp}/checksums.txt")"
if [[ -z "${expected}" ]]; then
  echo "checksum entry for ${archive} not found" >&2
  exit 1
fi
actual="$(shasum -a 256 "${tmp}/${archive}" | awk '{ print $1 }')"
if [[ "${actual}" != "${expected}" ]]; then
  echo "checksum mismatch for ${archive}" >&2
  echo "expected ${expected}" >&2
  echo "actual   ${actual}" >&2
  exit 1
fi

tar -C "${tmp}" -xzf "${tmp}/${archive}"
mkdir -p "${install_dir}"
cp "${tmp}/${name}/changegate" "${install_dir}/changegate"
chmod 0755 "${install_dir}/changegate"

"${install_dir}/changegate" version
