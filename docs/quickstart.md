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

The install script verifies the downloaded archive against `checksums.txt`. To also verify the signed checksum manifest, install `cosign` and set `CHANGEGATE_VERIFY_SIG=true` before running the same command.

Linux release packages are also published as `.deb`, `.rpm`, and `.apk` artifacts for package mirrors or runner images.

Docker:

```bash
docker run --rm ghcr.io/gabriel0110/changegate:vX.Y.Z version
docker run --rm -v "$PWD:/work:ro" ghcr.io/gabriel0110/changegate:vX.Y.Z scan --plan /work/tfplan.json
```

npm:

```bash
npx changegate version
npx changegate scan --plan tfplan.json
```

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

## 5. Create Starter Repository Files

Use `changegate init` when you want ChangeGate to scaffold safe starter files:

```bash
changegate init --dry-run
changegate init --github-actions --audit-mode
```

The generated policy uses audit mode by default. Add `--gitlab-ci`, `--waivers`, or `--baseline` when you want those files created too. Existing files are not overwritten unless you pass `--force`.

## 6. Generate A Shareable Report

```bash
changegate scan --plan tfplan.json --format markdown --out changegate.md
```

## 7. Archive Evidence

```bash
changegate scan --plan tfplan.json --audit-bundle changegate-audit.zip
```

The archive contains a browser-readable evidence report, canonical JSON report, decision evidence, redacted findings, policy and plan digests, scanner-import summary when used, and reproducibility notes.
