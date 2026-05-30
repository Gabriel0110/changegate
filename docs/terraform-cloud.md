# Terraform Cloud and Enterprise

Terraform Cloud and Terraform Enterprise expose plan JSON through their APIs and run-task integrations. ChangeGate does not need cloud provider credentials for the default scan path; it only needs the plan JSON.

## External Worker Pattern

1. Terraform Cloud creates a plan.
2. Your worker downloads or receives the plan JSON.
3. The worker runs:

```bash
changegate scan --plan tfplan.json --format json --out changegate.json --audit-bundle changegate-audit.zip
```

4. The worker maps `decision` to the run-task status.
5. The worker stores `changegate-audit.zip` in your evidence archive.

## Policy Choice

Use audit mode first:

```bash
changegate scan --plan tfplan.json --mode audit --format json --out changegate.json
```

Move to warning and blocking once owners have triaged existing risks.

## Multi-Workspace Runs

If a change spans multiple workspaces, scan each workspace independently when ownership differs. Use repeated `--plan` only when one policy owner is responsible for the coordinated change.
