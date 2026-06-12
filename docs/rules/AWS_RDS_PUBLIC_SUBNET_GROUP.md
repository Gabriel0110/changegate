# RDS uses a public subnet group

| Field | Value |
| --- | --- |
| Rule ID | `AWS_RDS_PUBLIC_SUBNET_GROUP` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects production or sensitive RDS resources placed in subnet groups that appear public.

## Resources

- `aws_db_instance`
- `aws_rds_cluster`
- `aws_db_subnet_group`
- `aws_subnet`

## Why It Matters

Public exposure changes can create reachable entrypoints. ChangeGate reports this when the plan or graph evidence is strong enough to show the exposure path.

## Remediation

- Remove public CIDRs unless internet access is required.
- Prefer private subnets, internal load balancers, or authenticated edge controls.
- Document any intentional public exposure in policy or a time-bounded waiver.

## References

- No external references.
