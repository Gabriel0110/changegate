# iam:PassRole grant in a compute-mutating plan

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PASSROLE_WITH_COMPUTE_MUTATION` |
| Category | `privilege_escalation` |
| Severity | `high` |
| Confidence | `medium` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-iam-escalation` |

## What It Detects

Detects iam:PassRole grants in plans that also mutate compute resources. The attack-path engine emits the high-confidence block when the same principal can both pass the role and mutate compute.

## Resources

- `aws_iam_policy`
- `aws_lambda_function`
- `aws_ecs_service`
- `aws_instance`

## Why It Matters

Privilege-escalation findings identify IAM changes that can expand who can assume roles, pass roles, mutate compute, or access sensitive resources.

## Remediation

- Replace wildcard actions and resources with least-privilege statements.
- Constrain trust policies to expected principals and conditions.
- Separate deploy-time permissions from runtime permissions.

## References

- No external references.
