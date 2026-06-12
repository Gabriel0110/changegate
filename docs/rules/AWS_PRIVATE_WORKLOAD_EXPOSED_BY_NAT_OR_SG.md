# Private workload allows public ingress

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PRIVATE_WORKLOAD_EXPOSED_BY_NAT_OR_SG` |
| Category | `network_blast_radius` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects changes that expose internal or private workload security boundaries through public ingress.

## Resources

- `aws_security_group`
- `aws_vpc_security_group_ingress_rule`

## Why It Matters

Network blast-radius findings identify routing or security-group changes that can expand reachable infrastructure paths.

## Remediation

- Avoid broad `0.0.0.0/0` routes from sensitive networks.
- Use explicit route tables for public and private tiers.
- Review transitive connectivity through peering and transit gateways.

## References

- No external references.
