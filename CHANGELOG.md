# Changelog

All notable changes to ChangeGate are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and ChangeGate uses semantic versioning before and after `v1.0`.

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
