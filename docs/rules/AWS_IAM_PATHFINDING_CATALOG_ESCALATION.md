# Pathfinding.cloud IAM escalation path

| Field | Value |
| --- | --- |
| Rule ID | `AWS_IAM_PATHFINDING_CATALOG_ESCALATION` |
| Category | `privilege_escalation` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-iam-escalation` |

## What It Detects

Detects IAM privilege-escalation prerequisites from the embedded Datadog pathfinding.cloud catalog.

## Resources

- `aws_iam_role`
- `aws_iam_user`
- `aws_iam_policy`
- `aws_codebuild_project`
- `aws_ecs_service`
- `aws_lambda_function`

## Why It Matters

The embedded pathfinding.cloud catalog captures known AWS IAM privilege-escalation chains; matching one means the plan grants a recognizable path to stronger access.

## Remediation

- Remove or narrow the IAM actions required by the matched escalation path.
- Scope resources to exact non-privileged targets and add restrictive IAM conditions where supported.
- Restrict iam:PassRole to approved service roles and use iam:PassedToService conditions when pass-role is involved.

## References

- https://github.com/Gabriel0110/changegate/blob/main/docs/attack-paths.md
- https://pathfinding.cloud/paths/
- https://github.com/DataDog/pathfinding.cloud
