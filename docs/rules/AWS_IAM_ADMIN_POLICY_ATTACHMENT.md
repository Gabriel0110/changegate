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

Privilege-escalation findings identify IAM changes that can expand who can assume roles, pass roles, mutate compute, or access sensitive resources.

## Remediation

- Replace wildcard actions and resources with least-privilege statements.
- Constrain trust policies to expected principals and conditions.
- Separate deploy-time permissions from runtime permissions.

## References

- No external references.
