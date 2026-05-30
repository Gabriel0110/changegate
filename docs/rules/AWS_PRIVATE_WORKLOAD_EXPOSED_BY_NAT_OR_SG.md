# Private workload exposed by NAT or security group change

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

Detects changes that expose internal or private workloads through public ingress or NAT routing.

## Resources

- `aws_security_group`
- `aws_vpc_security_group_ingress_rule`
- `aws_route`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.

