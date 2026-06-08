# IAM role assumption chain

| Field | Value |
| --- | --- |
| Rule ID | `AWS_IAM_ROLE_ASSUMPTION_CHAIN` |
| Category | `privilege_escalation` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-iam-escalation` |

## What It Detects

Detects multi-hop role assumption paths to administrator or sensitive roles.

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
