# Production CloudTrail log validation disabled

| Field       | Value                                              |
| ----------- | -------------------------------------------------- |
| Rule ID     | `AWS_CLOUDTRAIL_LOG_FILE_VALIDATION_DISABLED_PROD` |
| Category    | `compliance`                                       |
| Severity    | `high`                                             |
| Confidence  | `high`                                             |
| Status      | `stable`                                           |
| Version     | `0.1.0`                                            |
| Policy pack | `aws-core`                                         |

## What It Detects

Detects production or security CloudTrail trails without log file validation.

## Resources

- `aws_cloudtrail`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
