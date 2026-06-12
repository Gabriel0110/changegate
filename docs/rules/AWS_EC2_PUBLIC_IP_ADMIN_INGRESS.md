# EC2 instance has public IP and internet reachability

| Field | Value |
| --- | --- |
| Rule ID | `AWS_EC2_PUBLIC_IP_ADMIN_INGRESS` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects EC2 instances with public IPs that are reachable through the internet-facing graph.

## Resources

- `aws_instance`
- `aws_security_group`

## Why It Matters

Public exposure changes can create reachable entrypoints. ChangeGate reports this when the plan or graph evidence is strong enough to show the exposure path.

## Remediation

- Remove public CIDRs unless internet access is required.
- Prefer private subnets, internal load balancers, or authenticated edge controls.
- Document any intentional public exposure in policy or a time-bounded waiver.

## References

- No external references.
