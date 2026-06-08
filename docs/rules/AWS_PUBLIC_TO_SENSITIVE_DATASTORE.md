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

Detects public resources that can reach sensitive data stores through the graph.

## Resources

- `aws_lb`
- `aws_ecs_service`
- `aws_db_instance`
- `aws_s3_bucket`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
