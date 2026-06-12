# Internet-facing ALB routes to admin service

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PUBLIC_ADMIN_SERVICE` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects public load balancer paths to resources that appear to expose admin surfaces.

## Resources

- `aws_lb`
- `aws_lb_listener`
- `aws_lb_target_group`
- `aws_ecs_service`

## Why It Matters

Admin services should not be directly reachable from the public internet because they often provide privileged operational access.

## Remediation

- Set the ALB `internal` argument to `true` for private admin services.
- If public access is required, restrict listener security groups to VPN, zero-trust proxy, or allowlisted CIDRs.
- Confirm downstream services are not tagged as admin or production unless the exposure is intentional.

## References

- No external references.
