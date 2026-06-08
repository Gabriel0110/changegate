# Public workload can use sensitive KMS key

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PUBLIC_WORKLOAD_KMS_KEY_ACCESS` |
| Category | `sensitive_data` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects internet-exposed workloads with graph-backed access to sensitive KMS keys.

## Resources

- `aws_lambda_function`
- `aws_ecs_service`
- `aws_instance`
- `aws_kms_key`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.

