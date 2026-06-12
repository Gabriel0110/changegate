# Production RDS backup retention disabled

| Field | Value |
| --- | --- |
| Rule ID | `AWS_RDS_BACKUP_RETENTION_DISABLED_PROD` |
| Category | `availability` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-core` |

## What It Detects

Detects production databases with backup retention disabled or reduced to zero.

## Resources

- `aws_db_instance`
- `aws_rds_cluster`

## Why It Matters

Availability findings identify changes that can weaken recovery, deletion protection, or replacement safety for production or stateful resources.

## Remediation

- Set `backup_retention_period` to the required production value.
- Confirm backup windows and retention meet the service recovery objective.
- Apply through the normal database change process.

## References

- No external references.
