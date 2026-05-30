# Security Model

ChangeGate is designed to run in CI before infrastructure deployment.

## Trust Boundary

Inputs:

* Terraform/OpenTofu plan JSON
* optional `.changegate.yaml` policy
* optional baseline and waiver files
* optional offline cloud-context snapshot
* optional external scanner outputs

Outputs:

* allow/warn/block decision
* redacted reports
* audit evidence bundle
* SARIF/JUnit/Markdown/JSON integrations

## Default Offline Mode

The default scan path does not call cloud APIs, vendor services, or AI systems. It only reads local files and stdin.

## Secret Handling

The plan loader normalizes sensitive values and evidence is rendered through the redaction path. Audit bundles include the plan digest, not the raw plan JSON.

## Policy Decisions

Rules provide findings. The policy evaluator decides allow/warn/block using severity, confidence, suppression, baseline, waiver, environment, and changed-resource context. AI is not part of the decision path.

## Optional Cloud Context

Cloud context is opt-in and file-based:

```bash
changegate scan --plan tfplan.json --context-file .changegate/aws-context.json
```

Snapshots should contain read-only, redacted inventory context.

## Release Integrity

Official releases include checksums, signed checksums, SBOMs, attestations, and signed Docker images. See [release verification](release-verification.md).
