# Security group opens database port to the world

| Field       | Value                       |
| ----------- | --------------------------- |
| Rule ID     | `AWS_SG_WORLD_OPEN_DB_PORT` |
| Category    | `public_exposure`           |
| Severity    | `high`                      |
| Confidence  | `high`                      |
| Status      | `stable`                    |
| Version     | `0.1.0`                     |
| Policy pack | `aws-public-exposure`       |

## What It Detects

Detects public ingress to database ports.

## Resources

- `aws_security_group`
- `aws_vpc_security_group_ingress_rule`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
