# Production RDS backup retention reduced

| Field | Value |
| --- | --- |
| Rule ID | `AWS_RDS_BACKUP_RETENTION_REDUCED_PROD` |
| Category | `availability` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-core` |

## What It Detects

Detects production databases whose backup retention period is reduced.

## Resources

- `aws_db_instance`
- `aws_rds_cluster`

## Why It Matters

Availability findings identify changes that can weaken recovery, deletion protection, or replacement safety for production or stateful resources.

## Remediation

- Restore `backup_retention_period` to the previous or approved value.
- Confirm the reduction does not violate recovery requirements.
- Document any intentional retention reduction with approval.

## References

- No external references.
