# IAM Allow uses broad NotAction

| Field | Value |
| --- | --- |
| Rule ID | `AWS_IAM_NOTACTION_ALLOW_BROAD` |
| Category | `privilege_escalation` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-iam-escalation` |

## What It Detects

Detects Allow statements using NotAction with broad resource scope.

## Resources

- `aws_iam_policy`
- `aws_iam_role_policy`
- `aws_iam_user_policy`
- `aws_iam_group_policy`

## Why It Matters

Privilege-escalation findings identify IAM changes that can expand who can assume roles, pass roles, mutate compute, or access sensitive resources.

## Remediation

- Replace wildcard actions and resources with least-privilege statements.
- Constrain trust policies to expected principals and conditions.
- Separate deploy-time permissions from runtime permissions.

## References

- No external references.
