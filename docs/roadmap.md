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
* GitHub Actions, GitLab CI, Atlantis, and Terraform Cloud guidance
* signed release archives, checksums, SBOMs, and Docker images

## Experimental

Experimental capabilities may change before v1:

* broader cloud-context enrichment
* external scanner adapter normalization
* custom Rego policy workflows
* custom YAML policy workflows
* deeper compliance mapping
* richer remediation metadata

Experimental features must be documented as experimental in release notes when their behavior can affect CI outcomes.

## Planned

Planned work after the initial public release includes:

* ChangeGate Review Intelligence; see [implementation plan](review-intelligence-plan.md)
* additional AWS graph-aware rules based on false-positive data
* provider support beyond AWS
* stronger policy-pack versioning and compatibility reports
* reusable sanitized fixture library
* richer monorepo reporting
* expanded examples for platform teams
* package manager distribution beyond release archives and Homebrew

## Not Planned For MVP

The MVP intentionally defers:

* SaaS policy control
* telemetry
* LLM-based deploy decisions
* dynamic Go plugins
* IDE integrations
* large third-party policy marketplace
* full compliance dashboards
