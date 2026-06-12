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

Public workloads with secret access can turn a request-handling flaw into credential or data exposure.

## Remediation

- Remove unauthenticated public entry points that invoke the workload.
- Scope `secretsmanager:GetSecretValue` to only the secret and role that require it.
- Split public request handling from private secret access when the endpoint must remain internet-facing.

## References

- https://github.com/Gabriel0110/changegate/blob/main/docs/attack-paths.md
