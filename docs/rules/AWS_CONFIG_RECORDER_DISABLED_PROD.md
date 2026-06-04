# Production AWS Config recorder disabled

| Field       | Value                               |
| ----------- | ----------------------------------- |
| Rule ID     | `AWS_CONFIG_RECORDER_DISABLED_PROD` |
| Category    | `compliance`                        |
| Severity    | `high`                              |
| Confidence  | `high`                              |
| Status      | `stable`                            |
| Version     | `0.1.0`                             |
| Policy pack | `aws-core`                          |

## What It Detects

Detects production or security AWS Config recorders disabled by planned changes.

## Resources

- `aws_config_configuration_recorder`
- `aws_config_configuration_recorder_status`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
