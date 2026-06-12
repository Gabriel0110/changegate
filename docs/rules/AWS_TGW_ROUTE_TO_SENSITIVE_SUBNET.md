# Transit or peering route expands access to sensitive subnet

| Field | Value |
| --- | --- |
| Rule ID | `AWS_TGW_ROUTE_TO_SENSITIVE_SUBNET` |
| Category | `network_blast_radius` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects transit gateway or VPC peering routes that target sensitive or private route tables.

## Resources

- `aws_route`
- `aws_route_table`

## Why It Matters

Network blast-radius findings identify routing or security-group changes that can expand reachable infrastructure paths.

## Remediation

- Avoid broad `0.0.0.0/0` routes from sensitive networks.
- Use explicit route tables for public and private tiers.
- Review transitive connectivity through peering and transit gateways.

## References

- No external references.
