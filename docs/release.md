# Release Engineering

ChangeGate releases are designed to be repeatable and verifiable because the binary runs inside infrastructure pipelines.

## Go version policy

The minimum source compatibility version is Go 1.25, matching `go.mod`. Release and vulnerability-scan jobs use a patched Go toolchain, currently Go 1.26.3, so release artifacts do not ship known standard-library CVEs from older local toolchains.

## Release process

1. Ensure CI and security workflows are green on `main`.
2. Update `CHANGELOG.md` with the target version, including a `Breaking changes` section.
3. Tag the release:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

The release workflow:

* cross-compiles Linux, macOS, and Windows archives
* writes `checksums.txt`
* signs `checksums.txt` with keyless Cosign
* generates CycloneDX SBOMs for each archive
* uploads release artifacts
* generates GitHub artifact attestations
* builds and pushes the Docker image to GHCR
* signs the Docker image with keyless Cosign
* publishes a Homebrew formula when `HOMEBREW_TAP_REPOSITORY` and `HOMEBREW_TAP_TOKEN` are configured

## Local dry run

For a local artifact dry run without signing or SBOM tooling:

```bash
CHANGEGATE_SKIP_SBOM=1 CHANGEGATE_SKIP_SIGN=1 scripts/release-build.sh v0.0.0-dev
```

For a full local release candidate, install `syft` and `cosign` first and omit the skip variables.

## Reproducible build investigation

Release builds use `CGO_ENABLED=0`, `-trimpath`, and explicit build metadata. For byte-identical rebuild experiments, set `SOURCE_DATE_EPOCH` before running `scripts/release-build.sh`.

Known non-goals for the first release workflow:

* byte-identical Docker layers across registries
* verifying third-party GitHub-hosted runner images
* publishing to third-party package registries beyond the documented Homebrew tap handoff

## Changelog automation

GitHub release notes are categorized by `.github/release.yml`, and `scripts/release-notes.sh` emits a release-note body with a mandatory `Breaking changes` section.
