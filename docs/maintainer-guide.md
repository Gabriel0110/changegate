# Maintainer Guide

This guide captures the routine work needed to keep ChangeGate reliable for contributors and users.

## Triage

Use these labels as the first pass:

* `bug` for confirmed defects
* `false-positive` for findings that should not fire
* `rule-request` for new built-in rules
* `provider-support` for Terraform/OpenTofu provider coverage requests
* `good first issue` for small, well-scoped changes
* `needs-rfc` for changes that require design review
* `security` only for public hardening work, not private vulnerabilities

False-positive issues should include the fields requested by the issue template. If the report lacks a sanitized plan or enough evidence, ask for a reduced reproduction before changing rules.

## Pull Request Review

Before merging, confirm:

* tests cover changed behavior
* `go test ./...`, `go vet ./...`, `go test -race ./...`, and `golangci-lint run` pass
* user-visible behavior has docs
* policy-pack behavior changes have `CHANGELOG.md` entries
* generated rule docs are refreshed when rule metadata changes
* output schema changes are deliberate and documented

## Rule Changes

Treat stable rule behavior as release-critical. For stable rules, require at least one positive and one negative test. For graph-aware rules, require tests that prove the graph relationship changes the result.

When a false positive is fixed, keep a regression test with a sanitized fixture.

## Releases

Follow [release engineering](release.md) and [release verification](release-verification.md). Release candidates should include:

```bash
test -z "$(gofmt -l .)"
go test ./...
go vet ./...
go test -race ./...
golangci-lint run
scripts/release-notes.sh HEAD
```

Release artifacts should include checksums, signatures, SBOMs, Docker images, and artifact attestations.

## Deprecation

Deprecate public behavior before removal when practical. Rule IDs, schemas, exit codes, and config keys should not disappear without a release note and migration path.
