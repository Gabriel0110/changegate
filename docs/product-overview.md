# Product Overview

## Product Shape

ChangeGate is a Go single-binary CLI that analyzes Terraform/OpenTofu plan JSON before apply, builds a resource-risk graph for the change set, and returns one deployment decision: `allow`, `warn`, or `block`.

The tool is not a generic finding maximizer. It is a deploy gate optimized for low-noise, evidence-rich, high-confidence infrastructure risk decisions.

## Primary Users

The daily user is a developer or platform engineer reviewing or applying an infrastructure change.

The governance user is a security or platform engineer maintaining policies, waivers, baselines, and CI enforcement rules.

## Default User Journey

```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
changegate scan --plan tfplan.json
```

The default journey requires no cloud credentials, no SaaS account, no network access, and no scanner fan-out.

## Supported Inputs

* Terraform plan JSON produced by `terraform show -json`.
* OpenTofu-compatible plan JSON produced by `tofu show -json`.
* Optional `.changegate.yaml` policy configuration.

External scanner output, optional AWS cloud context snapshots, waivers, and baselines are available for existing-debt rollout and review context. Raw Terraform state ingestion remains a future extension; the primary supported input is still plan JSON from `terraform show -json` or `tofu show -json`.

## IaC and Provider Scope

* IaC engine: Terraform first, OpenTofu compatible.
* Cloud provider: AWS first.
* Rule posture: built-in high-confidence AWS policy packs before custom policy extensibility.

## Product Principles

* One binary, one command, one decision.
* No cloud credentials required for basic value.
* Block only high-confidence material risk.
* Explain every decision with evidence and remediation.
* Keep enforcement deterministic; AI may assist explanations later but must not decide.
* Adopt existing pipelines rather than requiring workflow migration.

## Built-in Policy Packs

* `aws-core`
* `aws-public-exposure`
* `aws-iam-escalation`

Additional packs are tracked on the public roadmap.

## Release and Security Posture

ChangeGate ships as a static Go binary with release artifacts, checksums, SBOMs, and provenance. The CLI avoids network calls unless the user explicitly requests a network-backed capability.

Debug logs must not print secrets, environment variables, or cloud credentials unless a future allowlist mechanism explicitly permits a specific key.

## Telemetry Posture

No telemetry and no network calls are allowed by default.

Any future telemetry must be explicit opt-in, documented, and disabled in CI unless configured by the user.

## Non-goals

* Generic raw HCL scanning is not the primary workflow.
* Native container scanning is out of scope.
* Cloud credentials are not required for default scans.
* AI does not make enforcement decisions.
* Broad multi-cloud coverage is not promised for early releases.
* A stable Go SDK is not part of the current public contract.
* Unsafe dynamic plugins are not supported.
