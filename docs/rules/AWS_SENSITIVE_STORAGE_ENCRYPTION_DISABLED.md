# Sensitive storage encryption disabled

| Field       | Value                                       |
| ----------- | ------------------------------------------- |
| Rule ID     | `AWS_SENSITIVE_STORAGE_ENCRYPTION_DISABLED` |
| Category    | `sensitive_data`                            |
| Severity    | `high`                                      |
| Confidence  | `high`                                      |
| Status      | `stable`                                    |
| Version     | `0.1.0`                                     |
| Policy pack | `aws-core`                                  |

## What It Detects

Detects sensitive storage resources with encryption disabled.

## Resources

- `aws_db_instance`
- `aws_rds_cluster`
- `aws_s3_bucket`
- `aws_efs_file_system`
- `aws_dynamodb_table`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
