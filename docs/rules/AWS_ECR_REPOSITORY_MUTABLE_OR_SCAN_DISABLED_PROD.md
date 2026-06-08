# Production ECR mutable tags or scan disabled

| Field | Value |
| --- | --- |
| Rule ID | `AWS_ECR_REPOSITORY_MUTABLE_OR_SCAN_DISABLED_PROD` |
| Category | `sensitive_data` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-core` |

## What It Detects

Detects production ECR repositories with mutable image tags or image scanning disabled.

## Resources

- `aws_ecr_repository`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
