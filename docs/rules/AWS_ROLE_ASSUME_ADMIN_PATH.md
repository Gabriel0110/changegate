# Role assumption path to admin role

| Field       | Value                        |
| ----------- | ---------------------------- |
| Rule ID     | `AWS_ROLE_ASSUME_ADMIN_PATH` |
| Category    | `privilege_escalation`       |
| Severity    | `high`                       |
| Confidence  | `high`                       |
| Status      | `stable`                     |
| Version     | `0.1.0`                      |
| Policy pack | `aws-iam-escalation`         |

## What It Detects

Detects graph paths that allow a principal to assume an administrator role.

## Resources

- `aws_iam_role`
- `aws_iam_policy`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
