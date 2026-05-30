# Public load balancer routes to internal service

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PUBLIC_INTERNAL_SERVICE` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects public load balancers routing to downstream services tagged internal.

## Resources

- `aws_lb`
- `aws_ecs_service`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.

