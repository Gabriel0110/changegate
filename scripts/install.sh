#!/usr/bin/env bash
set -euo pipefail

version="${CHANGEGATE_VERSION:-${1:-}}"
repo="${CHANGEGATE_REPO:-Gabriel0110/changegate}"
if [[ -n "${CHANGEGATE_INSTALL_DIR:-}" ]]; then
  install_dir="${CHANGEGATE_INSTALL_DIR}"
elif [[ "$(id -u)" == "0" ]]; then
  install_dir="/usr/local/bin"
else
  install_dir="${HOME}/.local/bin"
fi
verify_sig="${CHANGEGATE_VERIFY_SIG:-false}"

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

base="${CHANGEGATE_BASE_URL:-https://github.com/${repo}/releases/download/${version}}"
name="changegate_${version#v}_${os}_${arch}"
archive="${name}.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

curl -fsSL "${base}/${archive}" -o "${tmp}/${archive}"
curl -fsSL "${base}/checksums.txt" -o "${tmp}/checksums.txt"

case "${verify_sig}" in
  true|1|yes|YES|TRUE)
    command -v cosign >/dev/null 2>&1 || {
      echo "CHANGEGATE_VERIFY_SIG=true requires cosign on PATH" >&2
      exit 2
    }

    identity="${CHANGEGATE_COSIGN_CERT_IDENTITY:-https://github.com/${repo}/.github/workflows/release.yml@refs/tags/${version}}"
    issuer="${CHANGEGATE_COSIGN_CERT_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

    if curl -fsSL "${base}/checksums.txt.sigstore.json" -o "${tmp}/checksums.txt.sigstore.json"; then
      cosign verify-blob \
        --bundle "${tmp}/checksums.txt.sigstore.json" \
        --certificate-identity "${identity}" \
        --certificate-oidc-issuer "${issuer}" \
        "${tmp}/checksums.txt" >/dev/null
    else
      curl -fsSL "${base}/checksums.txt.sig" -o "${tmp}/checksums.txt.sig"
      curl -fsSL "${base}/checksums.txt.pem" -o "${tmp}/checksums.txt.pem"
      cosign verify-blob \
        --certificate "${tmp}/checksums.txt.pem" \
        --signature "${tmp}/checksums.txt.sig" \
        --certificate-identity "${identity}" \
        --certificate-oidc-issuer "${issuer}" \
        "${tmp}/checksums.txt" >/dev/null
    fi
    ;;
  false|0|no|NO|FALSE|"") ;;
  *)
    echo "CHANGEGATE_VERIFY_SIG must be true or false, got ${verify_sig}" >&2
    exit 2
    ;;
esac

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
