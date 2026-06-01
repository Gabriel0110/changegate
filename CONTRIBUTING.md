# Contributing

ChangeGate welcomes focused contributions that preserve the core product promise: one high-confidence infrastructure deployment decision, not more scanner noise.

## Before You Start

For bug fixes, open an issue or link to an existing issue. For new rules, policy behavior, output schemas, or large architecture changes, open a design discussion before implementation so the user impact can be reviewed early.

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

## Sensitive Data

Do not submit raw production plans, state files, provider debug logs, CI artifacts, secrets, account identifiers, private hostnames, or customer data. Use small synthetic examples and obvious placeholder values such as `123456789012`, `example`, `example.com`, and `redacted`.

## Release Notes

User-visible changes need a `CHANGELOG.md` entry. Policy pack changes need explicit release notes because they can alter CI outcomes.
