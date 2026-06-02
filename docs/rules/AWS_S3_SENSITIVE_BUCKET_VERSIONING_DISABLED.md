# Sensitive S3 bucket versioning disabled

| Field | Value |
| --- | --- |
| Rule ID | `AWS_S3_SENSITIVE_BUCKET_VERSIONING_DISABLED` |
| Category | `sensitive_data` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-core` |

## What It Detects

Detects sensitive buckets whose versioning is disabled or suspended.

## Resources

- `aws_s3_bucket`
- `aws_s3_bucket_versioning`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
