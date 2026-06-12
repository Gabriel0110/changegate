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

Public exposure changes can create reachable entrypoints. ChangeGate reports this when the plan or graph evidence is strong enough to show the exposure path.

## Remediation

- Remove public CIDRs unless internet access is required.
- Prefer private subnets, internal load balancers, or authenticated edge controls.
- Document any intentional public exposure in policy or a time-bounded waiver.

## References

- No external references.
