# Production RDS replacement

| Field | Value |
| --- | --- |
| Rule ID | `AWS_RDS_REPLACEMENT_PROD` |
| Category | `availability` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-core` |

## What It Detects

Detects replacement of production RDS instances.

## Resources

- `aws_db_instance`
- `aws_rds_cluster`

## Why It Matters

Availability findings identify changes that can weaken recovery, deletion protection, or replacement safety for production or stateful resources.

## Remediation

- Prefer in-place supported changes where possible.
- Snapshot the database immediately before apply.
- Schedule maintenance and document rollback.

## References

- No external references.
