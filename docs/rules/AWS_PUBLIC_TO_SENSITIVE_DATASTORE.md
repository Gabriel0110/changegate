# Public resource can reach sensitive datastore

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PUBLIC_TO_SENSITIVE_DATASTORE` |
| Category | `sensitive_data` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects public resources that can reach sensitive data stores through a high-confidence graph path.

## Resources

- `aws_lb`
- `aws_ecs_service`
- `aws_db_instance`
- `aws_s3_bucket`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Break the public-to-sensitive path with private networking, scoped security groups, or service isolation.
- Review the graph path evidence to identify the smallest edge to remove or constrain.

## References

- No external references.
