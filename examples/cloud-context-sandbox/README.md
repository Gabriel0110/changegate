# AWS Cloud Context Walkthrough

This walkthrough shows how to collect a redacted AWS context snapshot and use it in a local ChangeGate scan.

ChangeGate scans are offline by default. The collector is opt-in and writes a redacted snapshot that can be reviewed, stored as a CI artifact, and reused by later scans with `--context-file`.

## 1. Create Or Choose A Read-Only Role

Use the read-only collector policy in [examples/aws-context-readonly-policy.json](../aws-context-readonly-policy.json), or print the current policy template:

```bash
changegate context aws permissions-template
```

The role should be limited to read-only inventory APIs. It does not need permissions to create, update, or delete infrastructure.

## 2. Collect A Snapshot

Use an AWS profile that assumes the read-only role. Replace the profile, regions, and output path with values for your environment:

```bash
changegate context aws snapshot \
  --collect identity,network,edge,iam,compute,data \
  --profile readonly-inventory \
  --regions us-east-1,us-west-2 \
  --timeout 90s \
  --out .changegate/aws-context.json
```

Expected shape:

```json
{
  "ok": true,
  "command": "context aws snapshot",
  "result": {
    "provider": "aws",
    "collected": true,
    "regions": 1,
    "diagnostics": 0
  }
}
```

If permissions are missing, ChangeGate writes diagnostics into the snapshot result instead of failing the whole collection. This lets teams use partial context while seeing exactly which coverage is absent.

## 3. Validate Snapshot Coverage

```bash
changegate context aws validate-permissions \
  --context-file .changegate/aws-context.json
```

Capability flags are granular so partial-permission snapshots remain useful:

- `identity`
- `network`
- `security_groups`
- `edge`
- `elbv2`
- `cloudfront`
- `api_gateway`
- `iam`
- `compute`
- `ec2`
- `ecs`
- `lambda`
- `s3`
- `rds`
- `kms`
- `secrets_manager`
- `eks`

## 4. Scan With Offline Context

```bash
changegate scan \
  --plan tfplan.json \
  --context-file .changegate/aws-context.json
```

The scan reads the snapshot from disk. It does not call AWS during rule evaluation.

## Handling Snapshot Files

Treat context snapshots as environment-specific artifacts. Review them before sharing, store them only where CI artifacts or security evidence belong, and avoid committing snapshots from private accounts.

See [Cloud Context](../../docs/cloud-context.md) for schema details, merge behavior, and diagnostics.
