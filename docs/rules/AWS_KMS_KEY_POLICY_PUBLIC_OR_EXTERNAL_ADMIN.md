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

Privilege-escalation findings identify IAM changes that can expand who can assume roles, pass roles, mutate compute, or access sensitive resources.

## Remediation

- Replace wildcard actions and resources with least-privilege statements.
- Constrain trust policies to expected principals and conditions.
- Separate deploy-time permissions from runtime permissions.

## References

- No external references.
