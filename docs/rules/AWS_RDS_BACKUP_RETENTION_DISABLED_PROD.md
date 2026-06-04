# Production RDS backup retention disabled

| Field       | Value                                    |
| ----------- | ---------------------------------------- |
| Rule ID     | `AWS_RDS_BACKUP_RETENTION_DISABLED_PROD` |
| Category    | `availability`                           |
| Severity    | `high`                                   |
| Confidence  | `high`                                   |
| Status      | `stable`                                 |
| Version     | `0.1.0`                                  |
| Policy pack | `aws-core`                               |

## What It Detects

Detects production databases with backup retention disabled or reduced to zero.

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
