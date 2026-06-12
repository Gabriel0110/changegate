# Stateful resource replacement

| Field | Value |
| --- | --- |
| Rule ID | `AWS_STATEFUL_REPLACEMENT` |
| Category | `availability` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-core` |

## What It Detects

Detects destructive replacement of stateful resources.

## Resources

- `aws_db_instance`
- `aws_rds_cluster`
- `aws_efs_file_system`
- `aws_elasticache_cluster`
- `aws_dynamodb_table`

## Why It Matters

Availability findings identify changes that can weaken recovery, deletion protection, or replacement safety for production or stateful resources.

## Remediation

- Check the replacement path and confirm it is intended.
- Create a current backup or snapshot before apply.
- Plan a rollback or restore path before approving the change.

## References

- No external references.
