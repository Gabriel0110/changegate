# IAM NotAction escalation path

| Field | Value |
| --- | --- |
| Rule ID | `AWS_IAM_NOTACTION_ESCALATION_PATH` |
| Category | `privilege_escalation` |
| Severity | `high` |
| Confidence | `medium` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-iam-escalation` |

## What It Detects

Detects broad NotAction allow semantics that imply privilege-escalation permissions.

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
