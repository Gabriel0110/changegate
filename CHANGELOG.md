# Changelog

All notable changes to ChangeGate are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and ChangeGate uses semantic versioning before and after `v1.0`.

## v0.6.1 - 2026-06-30

### Changed

- Hardened custom Rego policy evaluation so runtime failures fail closed with a blocking `CUSTOM_OPA_REGO` finding instead of silently allowing the scan.
- Made release installers verify signed checksum manifests by default before trusting archive checksums.
- Capped untrusted Terraform/OpenTofu plan input, external scanner imports, custom Rego module files, audit plan hashing, and dense blast-radius graph traversal.
- Capped untrusted SARIF and generic imported findings at medium confidence unless native graph evidence or policy configuration raises their enforcement impact.
- Updated the minimum Go toolchain floor to `1.25.11` and adjusted CI to test the patched 1.25 line.

### Fixed

- Fixed terminal and Markdown/PR-rendered output paths so untrusted plan, finding, scanner, diagnostic, and remediation text is sanitized before human-facing rendering.
- Fixed AWS cloud-context coverage reporting so partial S3, Secrets Manager, and KMS policy-read failures are surfaced as diagnostics and no longer appear as complete policy coverage.
- Fixed npm publish workflow preparation so release package smoke tests have `cosign` available for signed checksum verification.

### Breaking changes

- Installers now require `cosign` by default for signed checksum verification. Set `CHANGEGATE_VERIFY_SIG=false` or `CHANGEGATE_NPM_VERIFY_SIG=false` only in trusted test environments where signature verification is intentionally unavailable.

## v0.6.0 - 2026-06-12

### Added

- Added regression coverage for IAM action/resource coupling, scoped deny handling, IAM wildcard resource matching, changed-only attack-path enforcement, and live-only cloud-context suppression.
- Added release preflight coverage for Docker runtime behavior and npm package installation before publishing release artifacts.

### Changed

- Tightened IAM attack-path detection to preserve statement-level action/resource semantics and apply Deny/NotResource evidence only to matching targets.
- Improved attack-path deduplication so equivalent paths collapse into stable, lower-noise findings and review output.
- Updated cloud-context enforcement so live AWS snapshot evidence enriches plan findings without blocking on unrelated live-only resources.
- Updated the AWS context collector read-only policy to include internet gateway inventory.
- Hardened npm publishing to check out the release tag, verify the release target commit, smoke-test the real release download path, and use the `npm-publish` environment.
- Updated install snippets, CI examples, and public docs to use release placeholders instead of stale version-specific examples.

### Fixed

- Fixed `--changed-only` handling for attack-path findings whose changed resource is a causal entrypoint or IAM policy rather than the terminal target.
- Fixed IAM false positives caused by flattening actions and resources across unrelated policy statements.
- Fixed IAM false negatives caused by treating scoped Deny statements as global action denies.
- Fixed resource matching that could confuse similarly named IAM ARNs.
- Fixed a missing `ec2:DescribeInternetGateways` permission in the AWS context collector policy template.
- Regenerated demo outputs after attack-path and graph evidence wording changes.

### Breaking changes

- None.

## v0.5.0 - 2026-06-08

### Added

- Added embedded DataDog/pathfinding.cloud IAM privilege-escalation catalog coverage for 86 AWS escalation paths.
- Added `AWS_IAM_PATHFINDING_CATALOG_ESCALATION` as a stable graph-aware attack-path rule with compliance mappings and rule documentation.
- Added a catalog updater script and third-party notice for the embedded defensive detection metadata.
- Added a risk-test fixture for a CodeBuild pass-role escalation path backed by the embedded catalog.

### Changed

- Improved IAM attack-path detection so catalog-backed paths include path IDs, required actions, services, upstream references, and conservative confidence handling.
- Updated attack-path documentation to describe catalog-backed IAM escalation behavior and attribution.

### Fixed

- Ensured catalog-backed attack paths map to their dedicated ChangeGate rule ID in scan reports.

### Breaking changes

- None.

## v0.4.0 - 2026-06-08

### Added

- Added official Docker distribution with non-root images, GHCR publishing, multi-architecture release support, OCI metadata, and Docker smoke tests.
- Added the `changegate` npm installer package with platform-specific binary resolution, checksum verification, a `changegate` CLI shim, and npm package smoke tests.
- Added user-facing install documentation for Docker and npm distribution paths.

### Changed

- Updated the release workflow so tagged releases can publish the npm package when `NPM_TOKEN` is configured.
- Updated CI to validate Docker image runtime behavior and npm package installation behavior before release.

### Fixed

- Kept generated npm vendor binaries out of git and Docker build contexts.

### Breaking changes

- None.

## v0.3.0 - 2026-06-08

### Added

- Expanded graph-aware AWS deployment-risk coverage for public API Gateway/Lambda paths, public workload access to sensitive data services, production resilience guardrails, IAM trust risks, KMS/S3 exposure, and network contradiction cases.
- Added AWS cloud-context snapshot v2 collection for richer read-only network, edge, compute, data, and IAM evidence while keeping default scans offline and credential-free.
- Added attack-path detection for public API Gateway and Lambda Function URL access to sensitive assets, public EKS endpoint to cluster-admin risk, IAM policy mutation escalation, broad `NotAction` escalation, and multi-hop role assumption chains.
- Added new stable attack-path rule IDs, rule reference pages, and default compliance mappings.

### Changed

- Improved attack-path confidence explanations so JSON, Markdown, review, and audit output explain why confidence is high, medium, or low.
- Tightened IAM policy parsing so `NotAction` and `NotResource` are handled as broad/ambiguous semantics instead of exact action/resource grants.
- Updated generated AWS rule documentation for the expanded stable ruleset.

### Fixed

- Reduced false-positive risk in IAM policy-mutation paths by requiring self, privileged, or sensitive target evidence instead of emitting broad wildcard target paths.

### Breaking changes

- None.

## v0.2.0 - 2026-06-02

### Added

- Expanded the built-in AWS stable ruleset to 53 high-confidence rules.
- Added stable AWS coverage for public S3 policies and ACLs, Lambda function URLs, admin API Gateway routes, weak public load balancer listeners, EFS and ElastiCache exposure, RDS public subnet groups, RDS backup/final-snapshot regressions, DynamoDB PITR, CloudTrail, AWS Config, ECR, KMS policy, and additional IAM wildcard/NotAction risks.
- Added rule reference pages and default compliance mappings for the new AWS rules.
- Added README guidance for external scanner imports with SARIF, Checkov, Trivy, KICS, and Grype examples.

### Changed

- GitLab CI validation now covers the GoReleaser packaging path used for release artifacts.
- README and release metadata now use normalized public license information.

### Fixed

- Removed leftover Apache license template appendix text from `LICENSE`.

### Breaking changes

- None.

## v0.1.0 - 2026-06-02

### Added

- Initial public release of ChangeGate.
- Plan-aware Terraform/OpenTofu scan engine with deterministic `ALLOW`, `WARN`, and `BLOCK` decisions.
- Built-in AWS rule pack, graph evidence, remediation metadata, baselines, waivers, audit bundles, SARIF, Markdown, JSON, JUnit, GitHub, and GitLab-oriented outputs.
- Review Intelligence commands for impact statements, graph inspection, attack paths, PR/MR comments, optional AWS context snapshots, and risk tests.
- Release archives, checksums, signed checksum bundles, SBOMs, provenance attestations, Docker images, Linux packages, and installer script.

### Changed

- None.

### Fixed

- None.

### Breaking changes

- None.
