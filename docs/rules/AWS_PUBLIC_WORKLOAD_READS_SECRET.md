# Public workload can read secret

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PUBLIC_WORKLOAD_READS_SECRET` |
| Category | `sensitive_data` |
| Severity | `critical` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects internet-exposed workloads with graph-backed access to Secrets Manager secrets.

## Resources

- `aws_lambda_function`
- `aws_ecs_service`
- `aws_instance`
- `aws_secretsmanager_secret`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
