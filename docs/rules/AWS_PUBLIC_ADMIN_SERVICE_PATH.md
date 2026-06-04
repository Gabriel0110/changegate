# Public admin service path

| Field       | Value                           |
| ----------- | ------------------------------- |
| Rule ID     | `AWS_PUBLIC_ADMIN_SERVICE_PATH` |
| Category    | `public_exposure`               |
| Severity    | `medium`                        |
| Confidence  | `medium`                        |
| Status      | `stable`                        |
| Version     | `0.1.0`                         |
| Policy pack | `aws-public-exposure`           |

## What It Detects

Detects public entrypoints reaching admin-like workloads without sensitive downstream context.

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

- docs/attack-paths.md
