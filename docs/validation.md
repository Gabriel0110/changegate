# Validation Evidence

This page collects reproducible evidence that ChangeGate is doing useful work, not only emitting generic scanner output.

## Canonical Demo

The primary proof fixture is [examples/demo-public-admin-path](../examples/demo-public-admin-path). It models:

```text
internet -> public ALB -> listener -> target group -> admin ECS service -> security group -> customer RDS
```

Expected result:

* deploy decision: `BLOCK`
* top finding: `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`
* attack path: `public_to_sensitive_data`
* critical evidence: public entrypoint reaches admin workload and sensitive datastore
* generated artifacts: Markdown report, Security Impact Statement, PR comment, Mermaid graph, interactive HTML graph, interactive HTML attack-path view, rendered SVG

## Runnable Corpus

The sanitized corpus at [examples/risk-tests](../examples/risk-tests) is executable documentation:

```bash
changegate test examples/risk-tests
```

It covers expected public web exposure, blocked public admin exposure, public-to-sensitive paths, Lambda URL to secret paths, IAM escalation paths, baseline behavior, waiver scoping, and cloud-context severity changes.

## Local Verification

Run the same checks used before release:

```bash
go test ./...
go test -race ./...
changegate test examples/risk-tests
```

For release packaging and CI validation, see [GitHub Actions](github-actions.md), [GitLab CI](gitlab-ci.md), [Output formats](output-formats.md), and [Audit evidence](audit-compliance.md).

## Evidence To Add Over Time

The next validation work should focus on real-world signal quality:

* run ChangeGate against a set of sanitized real Terraform/OpenTofu plans
* record false positives, false negatives, and confidence downgrades
* compare native ChangeGate findings with imported Checkov, Trivy, KICS, Grype, and SARIF findings
* publish representative terminal, PR/MR, SARIF, graph, and audit-bundle artifacts
* keep demos reproducible without requiring users to apply infrastructure
