# Private subnet route to internet gateway

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PRIVATE_SUBNET_ROUTE_TO_IGW` |
| Category | `network_blast_radius` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects route table changes that route private subnets to an internet gateway.

## Resources

- `aws_route`
- `aws_route_table`
- `aws_subnet`

## Why It Matters

Network blast-radius findings identify routing or security-group changes that can expand reachable infrastructure paths.

## Remediation

- Avoid broad `0.0.0.0/0` routes from sensitive networks.
- Use explicit route tables for public and private tiers.
- Review transitive connectivity through peering and transit gateways.

## References

- No external references.
