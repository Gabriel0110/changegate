# Production RDS deletion skips final snapshot

| Field | Value |
| --- | --- |
| Rule ID | `AWS_RDS_FINAL_SNAPSHOT_DISABLED_PROD` |
| Category | `availability` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-core` |

## What It Detects

Detects production database deletion or replacement configured to skip final snapshots.

## Resources

- `aws_db_instance`
- `aws_rds_cluster`

## Why It Matters

Availability findings identify changes that can weaken recovery, deletion protection, or replacement safety for production or stateful resources.

## Remediation

- Set `skip_final_snapshot = false` for production deletion or replacement.
- Provide a reviewed `final_snapshot_identifier` where required.
- Confirm the snapshot retention and restore plan before approving the change.

## References

- No external references.
