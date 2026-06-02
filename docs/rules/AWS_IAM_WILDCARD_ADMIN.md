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

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
