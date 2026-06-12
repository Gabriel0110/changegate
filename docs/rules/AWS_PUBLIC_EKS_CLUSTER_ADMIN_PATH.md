# Public EKS cluster-admin attack path

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PUBLIC_EKS_CLUSTER_ADMIN_PATH` |
| Category | `privilege_escalation` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-iam-escalation` |

## What It Detects

Detects public EKS control-plane exposure with graph evidence of cluster-admin or privileged role access.

## Resources

- `aws_eks_cluster`
- `aws_iam_role`
- `aws_iam_policy`

## Why It Matters

A public EKS endpoint combined with privileged cluster access can expose cluster administration to internet-originated attack paths.

## Remediation

- Restrict public EKS endpoint access to approved CIDRs or disable public endpoint access.
- Remove cluster-admin or privileged Kubernetes access from internet-reachable principals.
- Require private network access and short-lived, reviewed administrative access paths.

## References

- https://github.com/Gabriel0110/changegate/blob/main/docs/attack-paths.md
