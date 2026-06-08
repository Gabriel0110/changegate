# KMS key policy grants public or external administration

| Field | Value |
| --- | --- |
| Rule ID | `AWS_KMS_KEY_POLICY_PUBLIC_OR_EXTERNAL_ADMIN` |
| Category | `privilege_escalation` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-iam-escalation` |

## What It Detects

Detects KMS key policies that grant administrative or decrypt access to public or external principals.

## Resources

- `aws_kms_key`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
