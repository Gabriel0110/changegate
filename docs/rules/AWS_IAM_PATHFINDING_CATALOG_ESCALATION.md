# Pathfinding.cloud IAM escalation path

| Field       | Value                                    |
| ----------- | ---------------------------------------- |
| Rule ID     | `AWS_IAM_PATHFINDING_CATALOG_ESCALATION` |
| Category    | `privilege_escalation`                   |
| Severity    | `high`                                   |
| Confidence  | `high`                                   |
| Status      | `stable`                                 |
| Version     | `0.1.0`                                  |
| Policy pack | `aws-iam-escalation`                     |

## What It Detects

Detects IAM privilege-escalation prerequisites from ChangeGate's embedded Datadog pathfinding.cloud catalog snapshot.

## Resources

- `aws_iam_role`
- `aws_iam_user`
- `aws_iam_group`
- `aws_iam_policy`
- AWS compute and orchestration resources that can execute with an IAM role

## Why It Matters

Some IAM grants are dangerous only when combined with a service action, a passable role, or an existing resource that already runs with sensitive permissions. This rule turns known IAM privilege-escalation prerequisites into graph-backed attack-path evidence.

## Remediation

- Remove or narrow the IAM actions required by the matched path.
- Scope resources to exact non-privileged targets instead of wildcard resources.
- Restrict `iam:PassRole` to approved service roles and use `iam:PassedToService` conditions where supported.
- Review the path ID and involved services in the attack-path evidence.

## References

- docs/attack-paths.md
- https://pathfinding.cloud/paths/
- https://github.com/DataDog/pathfinding.cloud
