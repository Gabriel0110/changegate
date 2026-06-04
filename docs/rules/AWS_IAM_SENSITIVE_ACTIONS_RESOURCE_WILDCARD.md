# Sensitive IAM actions granted on wildcard resources

| Field       | Value                                         |
| ----------- | --------------------------------------------- |
| Rule ID     | `AWS_IAM_SENSITIVE_ACTIONS_RESOURCE_WILDCARD` |
| Category    | `privilege_escalation`                        |
| Severity    | `high`                                        |
| Confidence  | `high`                                        |
| Status      | `stable`                                      |
| Version     | `0.1.0`                                       |
| Policy pack | `aws-iam-escalation`                          |

## What It Detects

Detects secrets, KMS, SSM, or S3 data access granted on all resources.

## Resources

- `aws_iam_policy`
- `aws_iam_role_policy`
- `aws_iam_user_policy`
- `aws_iam_group_policy`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
