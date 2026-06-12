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

Sensitive-data findings indicate that a change can expose, weaken, or create access to data stores, secrets, or keys.

## Remediation

- Enable encryption with managed or customer-managed keys.
- Enable access logging or equivalent audit telemetry.
- Restrict access to the workloads that need the data.

## References

- No external references.
