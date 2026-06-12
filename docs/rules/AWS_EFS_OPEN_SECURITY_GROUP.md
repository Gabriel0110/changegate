# EFS allows broad network ingress

| Field | Value |
| --- | --- |
| Rule ID | `AWS_EFS_OPEN_SECURITY_GROUP` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects EFS mount targets attached to security groups with public ingress.

## Resources

- `aws_efs_mount_target`
- `aws_efs_file_system`
- `aws_security_group`

## Why It Matters

Public exposure changes can create reachable entrypoints. ChangeGate reports this when the plan or graph evidence is strong enough to show the exposure path.

## Remediation

- Remove public CIDRs unless internet access is required.
- Prefer private subnets, internal load balancers, or authenticated edge controls.
- Document any intentional public exposure in policy or a time-bounded waiver.

## References

- No external references.
