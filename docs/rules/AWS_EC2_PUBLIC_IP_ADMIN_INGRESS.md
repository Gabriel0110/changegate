# EC2 instance has public IP and admin ingress

| Field | Value |
| --- | --- |
| Rule ID | `AWS_EC2_PUBLIC_IP_ADMIN_INGRESS` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects EC2 instances with public IPs reachable through public admin ingress.

## Resources

- `aws_instance`
- `aws_security_group`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.

