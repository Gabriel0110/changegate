# Public API Gateway exposes admin route

| Field | Value |
| --- | --- |
| Rule ID | `AWS_API_GATEWAY_PUBLIC_ADMIN_ROUTE` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects public API Gateway routes or resources that appear to expose admin surfaces without authorization.

## Resources

- `aws_apigatewayv2_route`
- `aws_api_gateway_method`

## Why It Matters

Public exposure changes can create reachable entrypoints. ChangeGate reports this when the plan or graph evidence is strong enough to show the exposure path.

## Remediation

- Remove public CIDRs unless internet access is required.
- Prefer private subnets, internal load balancers, or authenticated edge controls.
- Document any intentional public exposure in policy or a time-bounded waiver.

## References

- No external references.
