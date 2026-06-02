# Public path reaches sensitive data

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH` |
| Category | `sensitive_data` |
| Severity | `critical` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects a graph-backed public entrypoint to sensitive data attack path.

## Resources

- `aws_lb`
- `aws_ecs_service`
- `aws_lambda_function`
- `aws_iam_role`
- `aws_iam_policy`
- `aws_db_instance`
- `aws_secretsmanager_secret`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Break the attack path by removing public exposure, sensitive reachability, or privilege escalation permissions.
- Scope IAM and network access to the minimum required resources.

## References

- ../attack-paths.md
