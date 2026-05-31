# Changelog

All notable changes to ChangeGate are documented here.

The format follows Keep a Changelog, and every release section must include a `Breaking changes` heading.

## Unreleased

### Added

* Initial release engineering assets: cross-platform builds, checksums, signing, SBOMs, provenance, Docker, Homebrew template, and GitHub Action wrapper.
* Review Intelligence command set:
  * `changegate impact` for Security Impact Statement JSON, Markdown, and deterministic impact audit bundles.
  * `changegate graph summary`, `graph path`, `graph exposure`, and `graph export` for Blast-Radius Graph v2 inspection.
  * `changegate review github` and `changegate review gitlab` for sticky PR/MR review comments, GitHub annotations, step summaries, and GitLab Code Quality artifact links.
  * `changegate attack-paths` for public-to-sensitive-data and IAM privilege-escalation path evidence.
  * `changegate context aws snapshot --collect` for optional read-only AWS context snapshots.
  * `changegate test` for Terraform/OpenTofu module risk regression tests.
* Audit bundle v2 evidence for impact statements, graph summaries, attack paths, cloud-context summaries, sticky review comments, risk-test metadata, waiver/baseline evidence, and run-task-compatible decision evidence.
* Sanitized example risk-test corpus and checked-in AWS read-only context policy example.

### Changed

* JSON reports may now include additional `run`, `audit`, `risk_movement`, `imports`, and `compliance` fields when the corresponding features are used.
* Graph JSON output now uses the Graph v2 schema only. Pre-release Graph v1 artifacts should be regenerated with `changegate graph export --plan tfplan.json --format json`.

### Experimental

* AWS cloud-context collection is opt-in, read-only, and narrow by design. It currently focuses on AWS network, edge, IAM, compute, and data relationships used by Review Intelligence; unsupported APIs and partial permissions are reported as diagnostics rather than hard failures.
* Attack Path v1 intentionally covers only high-signal public-to-sensitive-data and IAM escalation paths. It is not a full CSPM pathfinding engine.

### Deferred

* The self-hosted HCP Terraform run task adapter remains deferred. Current Terraform Cloud/Enterprise guidance uses the CLI from an external worker that already has access to plan JSON.

### Breaking changes

* None.
