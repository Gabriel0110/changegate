# ElastiCache allows broad network ingress

| Field       | Value                                 |
| ----------- | ------------------------------------- |
| Rule ID     | `AWS_ELASTICACHE_OPEN_SECURITY_GROUP` |
| Category    | `public_exposure`                     |
| Severity    | `high`                                |
| Confidence  | `high`                                |
| Status      | `stable`                              |
| Version     | `0.1.0`                               |
| Policy pack | `aws-public-exposure`                 |

## What It Detects

Detects ElastiCache clusters or replication groups attached to security groups with public ingress.

## Resources

- `aws_elasticache_cluster`
- `aws_elasticache_replication_group`
- `aws_security_group`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
