# Fixture Contributions

Fixtures are part of ChangeGate's security boundary. They make rules reproducible, but they must never leak customer data, secrets, account identifiers, private infrastructure names, or proprietary architecture.

## Allowed Fixture Sources

Good fixtures are:

* hand-written minimal plan fragments
* synthetic Terraform/OpenTofu plans from toy infrastructure
* reduced examples that preserve only fields needed by the rule
* scanner outputs produced from synthetic examples

Do not submit raw production plans, state files, provider debug logs, or CI artifacts.

## Redaction Checklist

Before opening a pull request, remove or replace:

* account IDs
* subscription or tenant IDs
* access keys and secret values
* ARNs that identify real accounts
* private DNS names
* private IP ranges when they reveal topology
* repository names from private organizations
* user names and email addresses
* customer, vendor, or project names
* certificate, key, token, and password material

Use obvious synthetic values such as `123456789012`, `example`, `example.com`, `redacted`, and `test`.

## Minimality

Keep fixtures small. A good fixture contains the smallest set of resources and attributes needed to prove the behavior being tested. Large fixtures are harder to review and increase the chance of leaking sensitive data.

## Verification

Run the relevant tests and the full suite before submitting:

```bash
go test ./internal/rules ./internal/graph ./internal/model
go test ./...
```

If a fixture changes policy output, regenerate affected docs and update `CHANGELOG.md`.

## False-Positive Reproductions

For false-positive reports, prefer a sanitized minimal reproduction over a full plan. If a full plan is unavoidable, remove every field that is not needed to reproduce the finding.
