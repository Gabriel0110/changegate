# Production RDS deletion protection disabled

| Field | Value |
| --- | --- |
| Rule ID | `AWS_RDS_DELETION_PROTECTION_DISABLED_PROD` |
| Category | `availability` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-core` |

## What It Detects

Detects production databases without deletion protection.

## Resources

- `aws_db_instance`
- `aws_rds_cluster`

## Why It Matters

Availability findings identify changes that can weaken recovery, deletion protection, or replacement safety for production or stateful resources.

## Remediation

- Set `deletion_protection = true` for production databases and clusters.
- Only disable deletion protection in a reviewed teardown or migration plan.
- Keep stateful deletion controls separate from routine configuration changes.

## References

- No external references.
