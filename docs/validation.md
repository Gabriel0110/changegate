# Verification Examples

This page shows how to run ChangeGate against bundled fixtures and inspect the kinds of decisions, findings, graph paths, and review artifacts it produces.

## Public Admin Path Demo

The [public admin path demo](../examples/demo-public-admin-path) uses a sanitized Terraform plan fixture that models:

```text
internet -> public ALB -> listener -> target group -> admin ECS service -> security group -> customer RDS
```

Running ChangeGate on this fixture produces:

* a `BLOCK` deploy decision
* an `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH` finding
* a `public_to_sensitive_data` attack path
* a Security Impact Statement
* PR/MR comment text
* Mermaid, SVG, and self-contained HTML graph visualizations

From the repository root:

```bash
changegate scan --plan examples/demo-public-admin-path/tfplan.json
changegate impact --plan examples/demo-public-admin-path/tfplan.json --format markdown
changegate attack-paths --plan examples/demo-public-admin-path/tfplan.json --format markdown
```

The demo includes pre-generated artifacts in [examples/demo-public-admin-path/outputs](../examples/demo-public-admin-path/outputs).

## Runnable Corpus

The [examples/risk-tests](../examples/risk-tests) corpus contains deterministic fixtures for common ChangeGate behavior:

```bash
changegate test examples/risk-tests
```

The corpus covers expected public web exposure, blocked public admin exposure, public-to-sensitive paths, Lambda URL to secret paths, IAM escalation paths, baseline behavior, waiver scoping, and cloud-context severity changes.

## Local Checks

When building ChangeGate from source, these commands provide a quick local check:

```bash
go test ./...
go test -race ./...
changegate test examples/risk-tests
```

For CI setup and output artifacts, see [GitHub Actions](github-actions.md), [GitLab CI](gitlab-ci.md), [Output formats](output-formats.md), and [Audit evidence](audit-compliance.md).
