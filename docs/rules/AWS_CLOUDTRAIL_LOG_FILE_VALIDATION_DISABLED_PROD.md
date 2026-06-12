# Production CloudTrail log validation disabled

| Field | Value |
| --- | --- |
| Rule ID | `AWS_CLOUDTRAIL_LOG_FILE_VALIDATION_DISABLED_PROD` |
| Category | `compliance` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-core` |

## What It Detects

Detects production or security CloudTrail trails without log file validation.

## Resources

- `aws_cloudtrail`

## Why It Matters

Compliance findings identify changes that weaken security logging, auditability, or required guardrails.

## Remediation

- Confirm whether the control applies to this environment.
- Update the resource configuration or add a time-bounded waiver with owner approval.
- Attach evidence to the pull request.

## References

- No external references.
