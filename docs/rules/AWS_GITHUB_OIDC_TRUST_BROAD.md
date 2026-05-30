# GitHub OIDC trust policy is too broad

| Field | Value |
| --- | --- |
| Rule ID | `AWS_GITHUB_OIDC_TRUST_BROAD` |
| Category | `privilege_escalation` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-iam-escalation` |

## What It Detects

Detects GitHub OIDC trust policies without repository or branch constraints.

## Resources

- `aws_iam_role`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.

