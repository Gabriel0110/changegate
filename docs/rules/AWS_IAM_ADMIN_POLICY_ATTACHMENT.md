# IAM administrator policy attachment

| Field | Value |
| --- | --- |
| Rule ID | `AWS_IAM_ADMIN_POLICY_ATTACHMENT` |
| Category | `privilege_escalation` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-iam-escalation` |

## What It Detects

Detects attachment of AdministratorAccess to IAM identities.

## Resources

- `aws_iam_role_policy_attachment`
- `aws_iam_user_policy_attachment`
- `aws_iam_group_policy_attachment`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.

