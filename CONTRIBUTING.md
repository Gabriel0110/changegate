# Contributing

ChangeGate welcomes focused contributions that preserve the core product promise: one high-confidence infrastructure deployment decision, not more scanner noise.

## Before You Start

For bug fixes, open an issue or link to an existing issue. For new rules, policy behavior, output schemas, or large architecture changes, open a design discussion before implementation so the behavior can be reviewed early.

## Development Setup

```bash
go mod download
go test ./...
go vet ./...
golangci-lint run
go build -o bin/changegate ./cmd/changegate
```

## Required Checks

Run these before opening a pull request:

```bash
test -z "$(gofmt -l .)"
go test ./...
go vet ./...
go test -race ./...
golangci-lint run
```

## Adding Rules

Rules must include:

* stable metadata
* tests with redacted fixtures
* remediation guidance
* policy pack and changelog updates when changing default coverage
* generated rule docs via `scripts/generate-rule-docs.sh docs/rules`

See [rule authoring](docs/rule-authoring.md).

## Fixtures

Fixtures must not contain secrets, account identifiers, private hostnames, or customer data. See [fixture contributions](docs/fixtures.md).

## Release Notes

User-visible changes need a `CHANGELOG.md` entry. Policy pack changes need explicit release notes because they can alter CI outcomes.
