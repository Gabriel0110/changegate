# Review Intelligence Release Notes

These notes summarize the Review Intelligence update for the first release candidate. They separate stable CLI behavior from experimental or deferred areas so adopters can choose the right rollout mode.

## Stable Features

* Security Impact Statement generation with `changegate impact` in Markdown and JSON.
* Blast-Radius Graph v2 commands:
  * `changegate graph summary`
  * `changegate graph path`
  * `changegate graph exposure`
  * `changegate graph export --format json`
* Sticky GitHub PR review comments, GitHub Actions annotations, and step summaries through `changegate review github`.
* Sticky GitLab MR review notes and GitLab Code Quality artifact links through `changegate review gitlab`.
* Attack Path v1 evidence through `changegate attack-paths`.
* Risk regression tests for Terraform/OpenTofu modules through `changegate test`.
* Read-only AWS context collection with redacted snapshot schema, granular capability flags, and partial-permission diagnostics.
* Audit bundle v2 with impact, graph, attack-path, waiver, baseline, cloud-context summary, review-comment, compliance, and redaction evidence.
* Sanitized runnable risk-test fixture corpus under `examples/risk-tests`.
* External scanner import normalization for SARIF, Checkov, Trivy, KICS, Grype, and generic JSON.
* Custom YAML and Rego policy workflows with validation-time schema, sandbox, and compile checks.
* Structured remediation metadata and compliance mappings, including organization-specific compliance mappings in `.changegate.yaml`.

## AWS Context Collection Scope

AWS context collection is opt-in and read-only:

```bash
changegate context aws snapshot --out .changegate/aws-context.json --collect
```

Current collection focuses on AWS relationships that improve Review Intelligence signal:

* network and security group exposure
* ALB/NLB, CloudFront, and API Gateway edge context
* IAM trust, role, policy, and OIDC metadata
* ECS, EKS, Lambda, and EC2 workload metadata
* RDS, S3, Secrets Manager, and KMS data metadata

Limitations:

* Unsupported APIs and partial permissions are diagnostics, not hard failures.
* Snapshots are summary/redacted context; they are not full cloud inventory exports.
* Default scans remain offline and do not call AWS.
* Additional AWS API coverage beyond the current collector and multi-cloud context collection remain future work.

## Attack Path v1 Scope

Attack Path v1 is intentionally narrow and deterministic. It covers:

* public entrypoint to workload to sensitive datastore, secret, or key
* principal to `iam:PassRole`, `sts:AssumeRole`, Lambda update, or ECS update paths that reach admin or sensitive access

It is not a full CSPM pathfinding engine. Ambiguous graph or IAM evidence lowers confidence and produces warning-oriented output instead of high-confidence blocking findings.

## Deferred HCP Terraform Adapter

The self-hosted HCP Terraform run task adapter remains deferred. This release does not ship a deployable adapter service, Docker Compose file, run task signature verifier, or HCP callback worker.

Current Terraform Cloud/Enterprise guidance is to run the `changegate` CLI from an external worker or CI job that already has access to plan JSON, then archive `changegate-audit.zip`.

## Migration Notes

No breaking CLI changes are expected for existing `changegate scan` usage.

JSON consumers should tolerate additive fields:

* scan reports may include `run`, `audit`, `risk_movement`, `imports`, and `compliance`
* audit bundles include new deterministic members under `changegate-audit/`
* impact statements use schema version `1`
* graph exports use Graph v2 only

Pre-release Graph v1 artifacts should be regenerated:

```bash
changegate graph export --plan tfplan.json --format json --out graph.json
```
