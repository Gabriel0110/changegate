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

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
