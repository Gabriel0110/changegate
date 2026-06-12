# Public path reaches sensitive data

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH` |
| Category | `sensitive_data` |
| Severity | `critical` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects a graph-backed public entrypoint to sensitive data attack path.

## Resources

- `aws_lb`
- `aws_api_gatewayv2_route`
- `aws_lambda_function_url`
- `aws_ecs_service`
- `aws_lambda_function`
- `aws_db_instance`
- `aws_secretsmanager_secret`

## Why It Matters

Public reachability becomes materially more important when the graph shows a route to admin functionality or sensitive data.

## Remediation

- Remove public reachability or require authenticated ingress for the entrypoint.
- Segment sensitive data stores, secrets, and keys from public workloads.
- Allow downstream sensitive access only from reviewed private workload identities or security groups.

## References

- https://github.com/Gabriel0110/changegate/blob/main/docs/attack-paths.md
