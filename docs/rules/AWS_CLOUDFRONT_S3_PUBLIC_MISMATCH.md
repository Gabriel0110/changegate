# CloudFront and S3 public exposure mismatch

| Field | Value |
| --- | --- |
| Rule ID | `AWS_CLOUDFRONT_S3_PUBLIC_MISMATCH` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects S3 buckets exposed publicly while also fronted by CloudFront.

## Resources

- `aws_cloudfront_distribution`
- `aws_s3_bucket`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
