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

This is stronger evidence than a standalone public endpoint finding because ChangeGate can trace the path from internet access to the sensitive asset.

## Remediation

- Set the function URL `authorization_type` to `AWS_IAM` or place it behind an authenticated edge layer.
- Remove secret, KMS, datastore, or bucket access that is not required by this public handler.
- If the function must stay public, split sensitive operations into a private worker role or separate function.

## References

- https://github.com/Gabriel0110/changegate/blob/main/docs/attack-paths.md
