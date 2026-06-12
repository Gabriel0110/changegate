# Public API Gateway reaches sensitive data

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PUBLIC_API_GATEWAY_TO_SENSITIVE_DATA` |
| Category | `sensitive_data` |
| Severity | `critical` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects unauthenticated public API Gateway paths that invoke a workload with graph-backed access to sensitive data.

## Resources

- `aws_apigatewayv2_api`
- `aws_api_gateway_rest_api`
- `aws_apigatewayv2_integration`
- `aws_api_gateway_integration`
- `aws_lambda_function`
- `aws_secretsmanager_secret`
- `aws_kms_key`
- `aws_s3_bucket`

## Why It Matters

This is a concrete public-to-sensitive path, not just a public endpoint setting.

## Remediation

- Set API Gateway route authorization to IAM, JWT, Cognito, or a reviewed custom authorizer.
- Confirm only authenticated routes can invoke workloads that read secrets, KMS keys, buckets, or datastores.
- Split public request handling from sensitive operations when the route must remain internet-facing.

## References

- https://github.com/Gabriel0110/changegate/blob/main/docs/attack-paths.md
