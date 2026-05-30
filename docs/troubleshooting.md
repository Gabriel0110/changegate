# Troubleshooting

## `missing required --plan path`

Generate plan JSON first:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
changegate scan --plan tfplan.json
```

## `unsupported plan format_version`

ChangeGate supports Terraform/OpenTofu plan JSON format major version `1.x`. Regenerate the JSON with a supported `terraform show -json` or `tofu show -json`.

## Invalid JSON

Confirm the file is not the binary plan:

```bash
file tfplan.json
jq empty tfplan.json
```

## Scan Blocks But The Risk Is Accepted

Use a scoped, expiring waiver:

```bash
changegate waiver add --file .changegate/waivers.yaml --rule AWS_PUBLIC_RDS_INSTANCE --resource aws_db_instance.main --owner platform --reason "temporary migration window" --expires-at 2026-07-01
```

Then reference it in policy.

## Existing Findings Block Adoption

Create a baseline:

```bash
changegate baseline create --plan tfplan.json --out .changegate/baseline.json
changegate scan --plan tfplan.json --baseline .changegate/baseline.json --new-only
```

## CI Output Is Too Large

Cap serialized findings:

```bash
changegate scan --plan tfplan.json --max-findings 100
```

The decision and risk summary still come from full evaluation.

## Cloud Context Does Not Apply

Cloud context is not used unless `--cloud-context aws` finds a cached snapshot or `--context-file` is passed. Default scans are plan-only.

## Where Error Messages Point

Common CLI errors include a `Fix:` line. Use this page for input and adoption errors, [policy config](config-schema.md) for policy errors, [waivers](waivers.md) for waiver errors, [baselines](baselines.md) for baseline errors, and [cloud context](cloud-context.md) for context file errors.
