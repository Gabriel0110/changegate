# Security group opens all ports to the world

| Field | Value |
| --- | --- |
| Rule ID | `AWS_SECURITY_GROUP_WORLD_OPEN_ALL_PORTS` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects public ingress that allows every port or protocol.

## Resources

- `aws_security_group`
- `aws_vpc_security_group_ingress_rule`

## Why It Matters

Public exposure changes can create reachable entrypoints. ChangeGate reports this when the plan or graph evidence is strong enough to show the exposure path.

## Remediation

- Remove public CIDRs unless internet access is required.
- Prefer private subnets, internal load balancers, or authenticated edge controls.
- Document any intentional public exposure in policy or a time-bounded waiver.

## References

- No external references.
