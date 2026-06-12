# S3 bucket policy grants public access

| Field | Value |
| --- | --- |
| Rule ID | `AWS_S3_BUCKET_PUBLIC_POLICY` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects S3 bucket policies that grant public read or write access.

## Resources

- `aws_s3_bucket_policy`

## Why It Matters

Public S3 policies can expose data directly, bypassing intended application, CloudFront, or identity controls.

## Remediation

- Remove `Principal: "*"` statements that grant S3 read or write access.
- Use CloudFront origin access control, a specific AWS principal, or an application role instead of public bucket policy access.
- Keep public access block enabled unless the bucket is intentionally public and reviewed.

## References

- No external references.
