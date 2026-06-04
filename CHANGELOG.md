# Changelog

All notable changes to ChangeGate are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and ChangeGate uses semantic versioning before and after `v1.0`.

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
