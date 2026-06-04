# Public API Gateway exposes admin route

| Field       | Value                                |
| ----------- | ------------------------------------ |
| Rule ID     | `AWS_API_GATEWAY_PUBLIC_ADMIN_ROUTE` |
| Category    | `public_exposure`                    |
| Severity    | `high`                               |
| Confidence  | `high`                               |
| Status      | `stable`                             |
| Version     | `0.1.0`                              |
| Policy pack | `aws-public-exposure`                |

## What It Detects

Detects public API Gateway routes or resources that appear to expose admin surfaces without authorization.

## Resources

- `aws_apigatewayv2_route`
- `aws_api_gateway_method`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
