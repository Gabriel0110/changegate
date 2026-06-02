# Transit or peering route expands access to sensitive subnet

| Field | Value |
| --- | --- |
| Rule ID | `AWS_TGW_ROUTE_TO_SENSITIVE_SUBNET` |
| Category | `network_blast_radius` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects transit gateway or VPC peering routes that target sensitive or private route tables.

## Resources

- `aws_route`
- `aws_route_table`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
