# Public load balancer uses weak TLS or plaintext HTTP

| Field | Value |
| --- | --- |
| Rule ID | `AWS_LOAD_BALANCER_WEAK_TLS_OR_HTTP` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects internet-facing load balancer listeners that use plaintext HTTP or legacy TLS policies.

## Resources

- `aws_lb`
- `aws_lb_listener`

## Why It Matters

Public exposure changes can create reachable entrypoints. ChangeGate reports this when the plan or graph evidence is strong enough to show the exposure path.

## Remediation

- Remove public CIDRs unless internet access is required.
- Prefer private subnets, internal load balancers, or authenticated edge controls.
- Document any intentional public exposure in policy or a time-bounded waiver.

## References

- No external references.
