# ChangeGate: ALLOW

| Metric | Value |
| --- | ---: |
| Risk clusters | 1 |
| Findings | 1 |
| Blocking | 0 |
| Warnings | 0 |
| Suppressed | 1 |
| Downgraded | 0 |
| Graph nodes | 2 |
| Graph edges | 2 |

## Decision reasons

- No findings met the configured block threshold.

## Risk clusters

### Public RDS instance

- Decision: `allow`
- Severity: `high`, confidence: `high`
- Affected resources: 1
- Supporting findings: 1
- Rules: `AWS_PUBLIC_RDS_INSTANCE`
- Primary fix: Set publicly_accessible to false and use private subnets.
- Resources: `aws_db_instance.customer`

## Finding details

### Public RDS instance

- Rule: `AWS_PUBLIC_RDS_INSTANCE`
- Resource: `aws_db_instance.customer`
- Severity: `high`, confidence: `high`
- Fingerprint: `ad371d9782ea54823b99e13534f56a23a596996c300a6fb951e6e92ff5448696`

Detects publicly accessible RDS instances.

Evidence:
- **Rule evidence:** database is configured as publicly accessible

Suppression:
- Existing baseline risk; not enforced in new-risk-only mode.
