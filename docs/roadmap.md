# Roadmap

This roadmap separates stable behavior from planned and experimental work so users can adopt ChangeGate without guessing which parts are dependable.

## Stable

Stable capabilities are intended for normal CI use:

* single-binary CLI
* Terraform plan JSON ingestion
* OpenTofu-compatible plan JSON ingestion
* AWS stable rule pack
* graph-aware risk analysis
* deterministic allow, warn, and block decisions
* console, JSON, Markdown, SARIF, and GitHub summary output
* baselines
* expiring waivers
* audit bundles
* ChangeGate Review Intelligence CLI commands: impact statements, Graph v2, PR/MR review comments, attack-path evidence, and risk tests
* AWS cloud-context snapshot schema and read-only collector with explicit partial-permission diagnostics
* external scanner import normalization for SARIF, Checkov, Trivy, KICS, Grype, and generic JSON
* custom YAML and Rego policy validation workflows
* compliance metadata for bundled stable AWS rules
* structured remediation metadata in JSON, SARIF, PR/MR comments, and audit bundles
* GitHub Actions, GitLab CI, Atlantis, and Terraform Cloud guidance
* signed release archives, checksums, SBOMs, Docker images, and Linux packages

## Experimental

Experimental capabilities may change before v1:

* additional AWS cloud-context API coverage beyond the current read-only collector
* multi-cloud context collection
* multi-plan external scanner correlation
* broad attack-path enforcement beyond the current deterministic v2 path types
* visual graph layout and UX iteration

Experimental behavior is called out in documentation when it can affect CI outcomes.

## Planned

Planned work after the initial public release includes:

* additional AWS graph-aware rules based on false-positive data
* provider support beyond AWS
* stronger policy-pack versioning and compatibility reports
* reusable sanitized fixture library
* richer monorepo reporting
* expanded examples for platform teams
* package manager distribution beyond release archives, Homebrew, and Linux packages

## Not Planned For MVP

The MVP intentionally defers:

* SaaS policy control
* telemetry
* LLM-based deploy decisions
* dynamic Go plugins
* IDE integrations
* large third-party policy marketplace
* full compliance dashboards
