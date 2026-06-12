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

Mutable production tags weaken release provenance, and disabled scanning reduces visibility into vulnerable images.

## Remediation

- Set `image_tag_mutability` to `IMMUTABLE` for production repositories.
- Enable `image_scanning_configuration.scan_on_push` or an equivalent registry scanning workflow.
- Use explicit release tags or digests for production deployment references.

## References

- No external references.
