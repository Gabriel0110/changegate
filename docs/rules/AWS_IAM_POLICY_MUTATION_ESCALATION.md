# IAM policy mutation escalation path

| Field | Value |
| --- | --- |
| Rule ID | `AWS_IAM_POLICY_MUTATION_ESCALATION` |
| Category | `privilege_escalation` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-iam-escalation` |

## What It Detects

Detects IAM policy mutation permissions that can create or promote privileged access.

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
