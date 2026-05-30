# Five-Minute Quickstart

This quickstart assumes Terraform or OpenTofu is already installed.

## 1. Build or Install ChangeGate

Development build:

```bash
go build -o bin/changegate ./cmd/changegate
```

Release install:

```bash
export CHANGEGATE_VERSION=vX.Y.Z
curl -fsSL "https://raw.githubusercontent.com/Gabriel0110/changegate/${CHANGEGATE_VERSION}/scripts/install.sh" | bash
```

## 2. Create A Plan JSON

Terraform:

```bash
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
```

OpenTofu:

```bash
tofu init
tofu plan -out=tfplan
tofu show -json tfplan > tfplan.json
```

## 3. Scan

```bash
changegate scan --plan tfplan.json
```

## 4. Generate A Shareable Report

```bash
changegate scan --plan tfplan.json --format markdown --out changegate.md
```

## 5. Archive Evidence

```bash
changegate scan --plan tfplan.json --audit-bundle changegate-audit.zip
```

The archive contains the decision, findings, suppressed findings, waiver and baseline reports when configured, policy digests, plan digest, rule pack versions, evidence JSON, compliance metadata, run metadata, and a Markdown summary.
