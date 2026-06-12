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

- `aws_iam_role`
- `aws_iam_user`
- `aws_iam_policy`
- `aws_lambda_function`
- `aws_ecs_service`

## Why It Matters

Privilege-escalation paths are higher risk than standalone IAM grants because they show how a principal can move from its current access to administrator or sensitive access.

## Remediation

- Remove or narrow the IAM actions that create the escalation path.
- Scope role assumption, pass-role, and policy mutation permissions to exact non-privileged resources.
- Add restrictive IAM conditions such as iam:PassedToService, repository/branch OIDC constraints, or explicit permission boundaries where applicable.

## References

- https://github.com/Gabriel0110/changegate/blob/main/docs/attack-paths.md
