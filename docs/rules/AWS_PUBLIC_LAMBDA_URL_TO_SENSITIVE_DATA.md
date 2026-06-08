# Public Lambda URL reaches sensitive data

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PUBLIC_LAMBDA_URL_TO_SENSITIVE_DATA` |
| Category | `sensitive_data` |
| Severity | `critical` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects unauthenticated Lambda function URLs that invoke a function with graph-backed access to sensitive data.

## Resources

- `aws_lambda_function_url`
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
