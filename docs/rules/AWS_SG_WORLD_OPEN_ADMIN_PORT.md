# Security group opens admin port to the world

| Field | Value |
| --- | --- |
| Rule ID | `AWS_SG_WORLD_OPEN_ADMIN_PORT` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects public ingress to administrative ports.

## Resources

- `aws_security_group`
- `aws_vpc_security_group_ingress_rule`

## Why It Matters

Public admin ports are high-value targets and are often exploited before application controls can help.

## Remediation

- Remove `0.0.0.0/0` and `::/0` from admin-port ingress rules.
- Use SSM Session Manager for instance access where possible.
- If network access is required, restrict `cidr_blocks` to a reviewed VPN or bastion CIDR.

## References

- No external references.
