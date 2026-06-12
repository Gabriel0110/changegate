# Public resource can reach sensitive datastore

| Field | Value |
| --- | --- |
| Rule ID | `AWS_PUBLIC_TO_SENSITIVE_DATASTORE` |
| Category | `sensitive_data` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects public resources that can reach sensitive data stores through the graph.

## Resources

- `aws_lb`
- `aws_ecs_service`
- `aws_db_instance`
- `aws_s3_bucket`

## Why It Matters

This is topology risk, not a missing storage control: a public-facing resource can reach a data asset that should be isolated.

## Remediation

- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.
- Remove direct routing from public workloads to sensitive datastores.
- Allow datastore access only from reviewed private workload security groups.

## References

- https://github.com/Gabriel0110/changegate/blob/main/docs/graph.md
- https://github.com/Gabriel0110/changegate/blob/main/docs/attack-paths.md
