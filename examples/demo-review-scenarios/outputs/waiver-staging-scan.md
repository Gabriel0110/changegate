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
- Fingerprint: `82141250226ad7c27ce4197a79f2d2308af330e8bcd39471913edf17ba0c23e6`

Detects publicly accessible RDS instances.

Evidence:
- **Rule evidence:** database is configured as publicly accessible

Suppression:
- WVR-STAGING-PUBLIC-RDS: Synthetic staging exception fixture. Production must not match this waiver.
