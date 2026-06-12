# Production DynamoDB point-in-time recovery disabled

| Field | Value |
| --- | --- |
| Rule ID | `AWS_DYNAMODB_PITR_DISABLED_PROD` |
| Category | `availability` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-core` |

## What It Detects

Detects production DynamoDB tables with point-in-time recovery disabled.

## Resources

- `aws_dynamodb_table`

## Why It Matters

Without PITR, accidental data corruption or deletion can become a longer outage or data-loss event.

## Remediation

- Set `point_in_time_recovery.enabled` to `true` for production tables.
- Confirm recovery-period requirements with the owning service before disabling PITR.
- Use a waiver only for intentionally ephemeral production tables with documented recovery alternatives.

## References

- No external references.
