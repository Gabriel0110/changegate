# Lambda function URL is public

| Field | Value |
| --- | --- |
| Rule ID | `AWS_LAMBDA_PUBLIC_FUNCTION_URL` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects Lambda function URLs that allow unauthenticated public access.

## Resources

- `aws_lambda_function_url`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
