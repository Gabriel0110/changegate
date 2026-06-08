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

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.

