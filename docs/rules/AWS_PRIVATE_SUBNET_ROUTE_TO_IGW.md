# Private subnet route to internet gateway

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PRIVATE_SUBNET_ROUTE_TO_IGW` |
| Category | `network_blast_radius` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects route table changes that route private subnets to an internet gateway.

## Resources

- `aws_route`
- `aws_route_table`
- `aws_subnet`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.

