# ChangeGate: BLOCK

| Metric        | Value |
| ------------- | ----: |
| Risk clusters |     1 |
| Findings      |     1 |
| Blocking      |     1 |
| Warnings      |     0 |
| Suppressed    |     0 |
| Downgraded    |     0 |
| Graph nodes   |     2 |
| Graph edges   |     2 |

## Decision reasons

- `MEETS_BLOCK_THRESHOLD` `Public RDS instance`: finding meets block threshold

## Risk clusters

### Public RDS instance

- Decision: `block`
- Severity: `high`, confidence: `high`
- Affected resources: 1
- Supporting findings: 1
- Rules: `AWS_PUBLIC_RDS_INSTANCE`
- Primary fix: Set publicly_accessible to false and use private subnets.
- Resources: `aws_db_instance.customer`

## Finding details

### Public RDS instance

- Rule: `AWS_PUBLIC_RDS_INSTANCE`
- Resource: `aws_db_instance.customer`
- Severity: `high`, confidence: `high`
- Fingerprint: `ad371d9782ea54823b99e13534f56a23a596996c300a6fb951e6e92ff5448696`

Detects publicly accessible RDS instances.

Evidence:

- `rule` `publicly_accessible`: database is configured as publicly accessible

Remediation:

- Set publicly_accessible to false and use private subnets.
- Restrict security groups to application sources only.
- Set `publicly_accessible = false`.
- Use private DB subnet groups.
- Why this works: The database no longer receives public network exposure and is reachable only through private routing.
- Fix confidence: `high`
- Automatic patch: `false`

Patch suggestion: Disable public RDS accessibility

```hcl
resource "aws_db_instance" "customer" {
  publicly_accessible = false
  db_subnet_group_name = aws_db_subnet_group.private.name
}
```

- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.
