# ChangeGate Product Spec

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

The default journey must require no cloud credentials, no SaaS account, no network access, and no scanner fan-out.

## v0.1 Supported Inputs

* Terraform plan JSON produced by `terraform show -json`.
* OpenTofu-compatible plan JSON produced by `tofu show -json`.
* Optional `.changegate.yaml` policy configuration.

State JSON, external scanner output, live cloud context, and waivers are planned extensions. Baselines are available for existing-debt rollout.

## v0.1 IaC and Provider Scope

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

## Initial Built-in Policy Packs

* `aws-core`
* `aws-public-exposure`
* `aws-iam-escalation`

Additional packs can be added after the rule engine and finding model stabilize.

## Release and Security Posture

ChangeGate should ship as a static Go binary with reproducible release artifacts, checksums, signed releases, SBOMs, and provenance. The CLI must avoid network calls unless the user explicitly requests a network-backed capability.

Debug logs must not print secrets, environment variables, or cloud credentials unless a future allowlist mechanism explicitly permits a specific key.

## Telemetry Posture

No telemetry and no network calls are allowed by default.

Any future telemetry must be explicit opt-in, documented, and disabled in CI unless configured by the user.

## v1 Non-goals

* Do not build a generic raw HCL scanner first.
* Do not build native container scanning first.
* Do not require cloud credentials.
* Do not make AI part of enforcement.
* Do not support every cloud in v1.
* Do not expose a stable Go SDK before the internal engine stabilizes.
* Do not implement unsafe dynamic plugins in v1.

## Public Roadmap Boundary

The public roadmap should emphasize plan-aware analysis, graph-aware risk, low-noise deployment decisions, stable audit evidence, CI adoption, baselines, waivers, and secure single-binary distribution.

The roadmap should avoid implying near-term support for SaaS policy control, broad multi-cloud coverage, IDE workflows, dynamic plugin marketplaces, or AI-based enforcement.
