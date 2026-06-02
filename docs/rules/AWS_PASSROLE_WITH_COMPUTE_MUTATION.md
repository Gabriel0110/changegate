# iam:PassRole with compute mutation

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PASSROLE_WITH_COMPUTE_MUTATION` |
| Category | `privilege_escalation` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-iam-escalation` |

## What It Detects

Detects IAM principals that can pass roles and mutate compute resources.

## Resources

- `aws_iam_policy`
- `aws_lambda_function`
- `aws_ecs_service`
- `aws_instance`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
