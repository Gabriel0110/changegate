# Wildcard IAM administration

| Field | Value |
| --- | --- |
| Rule ID | `AWS_IAM_WILDCARD_ADMIN` |
| Category | `privilege_escalation` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-iam-escalation` |

## What It Detects

Detects IAM policies with broad iam:* or Action:* grants.

## Resources

- `aws_iam_policy`
- `aws_iam_role_policy`

## Why It Matters

Privilege-escalation findings identify IAM changes that can expand who can assume roles, pass roles, mutate compute, or access sensitive resources.

## Remediation

- Replace wildcard actions and resources with least-privilege statements.
- Constrain trust policies to expected principals and conditions.
- Separate deploy-time permissions from runtime permissions.

## References

- No external references.
