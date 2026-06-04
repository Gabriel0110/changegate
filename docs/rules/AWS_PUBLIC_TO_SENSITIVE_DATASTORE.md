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

This is topology risk, not a missing storage control. A public-facing resource can reach a sensitive datastore, which increases the chance that an exposed workload becomes a data exposure path.

## Remediation

- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.
- Remove direct routing from public workloads to sensitive datastores.
- Allow datastore access only from reviewed private workload security groups.
- Treat automatic patching as unsafe for this rule; the correct fix depends on service ownership, routing intent, security groups, and approved access patterns.

## References

- [Blast-Radius Graph](../graph.md)
- [Attack Paths](../attack-paths.md)
