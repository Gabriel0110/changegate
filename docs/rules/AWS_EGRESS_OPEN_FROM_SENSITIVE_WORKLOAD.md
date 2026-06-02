# Sensitive workload egress opened to internet

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

Detects broad egress from sensitive workloads.

## Resources

- `aws_security_group`
- `aws_vpc_security_group_egress_rule`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
