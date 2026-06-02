# Production S3 public access block disabled

| Field | Value |
| --- | --- |
| Rule ID | `AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED_PROD` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects production S3 public access block resources that disable one or more protections.

## Resources

- `aws_s3_bucket_public_access_block`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
