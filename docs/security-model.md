# Security Model

ChangeGate is designed to run in CI before infrastructure deployment.

## Trust Boundary

Inputs:

- Terraform/OpenTofu plan JSON
- optional `.changegate.yaml` policy
- optional baseline and waiver files
- optional offline cloud-context snapshot
- optional external scanner outputs

Outputs:

- allow/warn/block decision
- redacted reports
- audit evidence bundle
- SARIF/JUnit/Markdown/JSON integrations

## Default Offline Mode

The default scan path does not call cloud APIs, vendor services, or AI systems. It only reads local files and stdin.

## Secret Handling

The plan loader normalizes sensitive values and evidence is rendered through the redaction path. Audit bundles include the plan digest, not the raw plan JSON.

Review integrations resolve provider tokens from environment variables by default and redact known token values from provider API errors before returning diagnostics. Review comments escape untrusted Markdown/HTML fragments from findings, diagnostics, ownership hints, and artifact labels.

Audit bundles include a cloud-context summary by default: provider, generation time, regions, capabilities, resource counts, relationship count, and diagnostics. They do not include the full cloud inventory snapshot unless a caller explicitly stores that snapshot separately.

## Policy Decisions

Rules provide findings. The policy evaluator decides allow/warn/block using severity, confidence, suppression, baseline, waiver, environment, and changed-resource context. AI is not part of the decision path.

## Optional Cloud Context

Cloud context is opt-in and file-based:

```bash
changegate scan --plan tfplan.json --context-file .changegate/aws-context.json
```

Snapshots should contain read-only, redacted inventory context.

## Networked Integrations

`changegate review github` and `changegate review gitlab` call only the provider comment APIs needed to create or update the sticky review comment. HTTP clients use fixed timeouts, bounded JSON request bodies, bounded provider responses, and bounded provider error bodies.

For untrusted pull requests, do not run arbitrary repository code or Terraform module hooks in a workflow that has a write-capable review token. Generate plans with read-only credentials, post comments from trusted workflow context, and keep GitHub/GitLab tokens least-privilege and masked.

## Download Integrity

Release downloads include checksums, signed checksums, SBOMs, attestations, signed Docker images, and Linux `.deb`, `.rpm`, and `.apk` packages.

The install script verifies the signed checksum manifest by default before trusting `checksums.txt`, then verifies the downloaded archive against that manifest. This requires `cosign` on PATH. Set `CHANGEGATE_VERIFY_SIG=false` only in trusted test environments where signature verification is intentionally unavailable.
