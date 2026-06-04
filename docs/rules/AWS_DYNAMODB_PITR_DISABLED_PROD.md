# Production DynamoDB point-in-time recovery disabled

| Field       | Value                             |
| ----------- | --------------------------------- |
| Rule ID     | `AWS_DYNAMODB_PITR_DISABLED_PROD` |
| Category    | `availability`                    |
| Severity    | `high`                            |
| Confidence  | `high`                            |
| Status      | `stable`                          |
| Version     | `0.1.0`                           |
| Policy pack | `aws-core`                        |

## What It Detects

Detects production DynamoDB tables with point-in-time recovery disabled.

## Resources

- `aws_dynamodb_table`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
