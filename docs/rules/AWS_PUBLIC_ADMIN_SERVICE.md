# Internet-facing ALB routes to admin service

| Field       | Value                      |
| ----------- | -------------------------- |
| Rule ID     | `AWS_PUBLIC_ADMIN_SERVICE` |
| Category    | `public_exposure`          |
| Severity    | `high`                     |
| Confidence  | `high`                     |
| Status      | `stable`                   |
| Version     | `0.1.0`                    |
| Policy pack | `aws-public-exposure`      |

## What It Detects

Detects public load balancer paths to resources that appear to expose admin surfaces.

## Resources

- `aws_lb`
- `aws_lb_listener`
- `aws_lb_target_group`
- `aws_ecs_service`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
