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

Unauthenticated function URLs are direct public entry points; risk increases when the function can reach secrets, data stores, or privileged APIs.

## Remediation

- Set the Lambda function URL `authorization_type` to `AWS_IAM` when callers can sign requests.
- If anonymous access is required, put the function behind API Gateway, CloudFront, WAF, or another reviewed edge control.
- Document any intentionally public function URL with owner approval and monitoring coverage.

## References

- No external references.
