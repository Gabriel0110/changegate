# Public load balancer uses weak TLS or plaintext HTTP

| Field | Value |
| --- | --- |
| Rule ID | `AWS_LOAD_BALANCER_WEAK_TLS_OR_HTTP` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects internet-facing load balancer listeners that use plaintext HTTP or legacy TLS policies.

## Resources

- `aws_lb`
- `aws_lb_listener`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
