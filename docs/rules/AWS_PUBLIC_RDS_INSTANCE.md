# Public RDS instance

| Field       | Value                     |
| ----------- | ------------------------- |
| Rule ID     | `AWS_PUBLIC_RDS_INSTANCE` |
| Category    | `public_exposure`         |
| Severity    | `high`                    |
| Confidence  | `high`                    |
| Status      | `stable`                  |
| Version     | `0.1.0`                   |
| Policy pack | `aws-public-exposure`     |

## What It Detects

Detects publicly accessible RDS instances.

## Resources

- `aws_db_instance`
- `aws_rds_cluster`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
