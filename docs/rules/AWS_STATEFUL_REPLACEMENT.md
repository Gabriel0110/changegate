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

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.

