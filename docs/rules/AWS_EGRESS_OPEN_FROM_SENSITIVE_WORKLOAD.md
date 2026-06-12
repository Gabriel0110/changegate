# Production security group opens broad egress

| Field | Value |
| --- | --- |
| Rule ID | `AWS_EGRESS_OPEN_FROM_SENSITIVE_WORKLOAD` |
| Category | `network_blast_radius` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects production security groups that open broad egress to the internet.

## Resources

- `aws_security_group`
- `aws_vpc_security_group_egress_rule`

## Why It Matters

Network blast-radius findings identify routing or security-group changes that can expand reachable infrastructure paths.

## Remediation

- Avoid broad `0.0.0.0/0` routes from sensitive networks.
- Use explicit route tables for public and private tiers.
- Review transitive connectivity through peering and transit gateways.

## References

- No external references.
