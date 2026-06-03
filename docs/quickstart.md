# Five-Minute Quickstart

This quickstart assumes Terraform or OpenTofu is already installed.

## 1. Build or Install ChangeGate

Development build:

```bash
go build -o bin/changegate ./cmd/changegate
```

Release install:

```bash
export CHANGEGATE_VERSION=v0.2.0
curl -fsSL "https://raw.githubusercontent.com/Gabriel0110/changegate/${CHANGEGATE_VERSION}/scripts/install.sh" | bash
```

Linux release packages are also published as `.deb`, `.rpm`, and `.apk` artifacts for teams that install CLI tools through package mirrors or runner images.

## 2. Try The Demo

```bash
changegate scan --plan examples/demo-public-admin-path/tfplan.json
```

Expected result: `BLOCK`. The demo shows a public ALB reaching an admin ECS service with a path to customer RDS. See [the demo README](../examples/demo-public-admin-path) for generated Security Impact Statement, PR comment, graph, and attack-path outputs.

## 3. Create A Plan JSON

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

## 4. Scan

```bash
changegate scan --plan tfplan.json
```

## 5. Generate A Shareable Report

```bash
changegate scan --plan tfplan.json --format markdown --out changegate.md
```

## 6. Archive Evidence

```bash
changegate scan --plan tfplan.json --audit-bundle changegate-audit.zip
```

The archive contains the decision, findings, suppressed findings, waiver and baseline reports when configured, policy digests, plan digest, rule pack versions, evidence JSON, compliance metadata, run metadata, and a Markdown summary.
