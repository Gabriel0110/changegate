# ChangeGate: ALLOW

| Metric | Value |
| --- | ---: |
| Risk clusters | 1 |
| Findings | 1 |
| Blocking | 0 |
| Warnings | 0 |
| Suppressed | 1 |
| Downgraded | 0 |
| Graph nodes | 2 |
| Graph edges | 2 |

## Decision reasons

- `BELOW_BLOCK_THRESHOLD`: findings did not meet block threshold

## Risk clusters

### Public RDS instance

- Decision: `allow`
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
- Fingerprint: `82141250226ad7c27ce4197a79f2d2308af330e8bcd39471913edf17ba0c23e6`

Detects publicly accessible RDS instances.

Evidence:
- **Rule evidence:** database is configured as publicly accessible

Remediation:

**Primary fix:** Set publicly_accessible to false and use private subnets.

Recommended actions:
- Restrict security groups to application sources only.
- Set `publicly_accessible = false`.
- Use private DB subnet groups.

Fix options:
- **Make the endpoint private** (preferred): Move the exposed resource behind private networking or an internal load balancer.
- **Restrict ingress**: Keep the endpoint public only for reviewed CIDRs or authenticated edge controls.

Patch suggestion: Disable public RDS accessibility

```hcl
resource "aws_db_instance" "customer" {
  publicly_accessible = false
  db_subnet_group_name = aws_db_subnet_group.private.name
}
```

Review the patch before applying it.

Review notes:
- Effort: medium
- Downtime risk: medium
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.
