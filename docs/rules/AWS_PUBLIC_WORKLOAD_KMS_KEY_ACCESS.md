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

Publicly reachable code with decrypt access can become a data exposure path if the workload is compromised.

## Remediation

- Restrict the public entrypoint with authentication or approved CIDRs.
- Scope `kms:Decrypt` to the exact key and private workload role that requires it.
- Separate public request handling from code paths that decrypt sensitive data.

## References

- https://github.com/Gabriel0110/changegate/blob/main/docs/attack-paths.md
