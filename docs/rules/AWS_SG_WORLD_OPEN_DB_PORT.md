# Security group opens database port to the world

| Field | Value |
| --- | --- |
| Rule ID | `AWS_SG_WORLD_OPEN_DB_PORT` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects public ingress to database ports.

## Resources

- `aws_security_group`
- `aws_vpc_security_group_ingress_rule`

## Why It Matters

Public exposure changes can create reachable entrypoints. ChangeGate reports this when the plan or graph evidence is strong enough to show the exposure path.

## Remediation

- Delete public CIDR ingress on database ports.
- Use `source_security_group_id` for application-to-database access.
- Keep database resources in private subnets.

## References

- No external references.
