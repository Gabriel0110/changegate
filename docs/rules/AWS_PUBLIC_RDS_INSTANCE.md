# Public RDS instance

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PUBLIC_RDS_INSTANCE` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects publicly accessible RDS instances.

## Resources

- `aws_db_instance`
- `aws_rds_cluster`

## Why It Matters

Public exposure changes can create reachable entrypoints. ChangeGate reports this when the plan or graph evidence is strong enough to show the exposure path.

## Remediation

- Set `publicly_accessible = false`.
- Use private DB subnet groups.
- Restrict security groups to application sources only.

## References

- No external references.
