# Production EKS endpoint is public

| Field       | Value                          |
| ----------- | ------------------------------ |
| Rule ID     | `AWS_PUBLIC_EKS_ENDPOINT_PROD` |
| Category    | `public_exposure`              |
| Severity    | `high`                         |
| Confidence  | `high`                         |
| Status      | `stable`                       |
| Version     | `0.1.0`                        |
| Policy pack | `aws-public-exposure`          |

## What It Detects

Detects production EKS clusters with public endpoints enabled.

## Resources

- `aws_eks_cluster`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
