# Public workload can access sensitive S3 data

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PUBLIC_WORKLOAD_S3_DATA_ACCESS` |
| Category | `sensitive_data` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects internet-exposed workloads with graph-backed read or write access to sensitive S3 buckets.

## Resources

- `aws_lambda_function`
- `aws_ecs_service`
- `aws_instance`
- `aws_s3_bucket`

## Why It Matters

Sensitive-data findings indicate that a change can expose, weaken, or create access to data stores, secrets, or keys.

## Remediation

- Enable encryption with managed or customer-managed keys.
- Enable access logging or equivalent audit telemetry.
- Restrict access to the workloads that need the data.

## References

- No external references.
