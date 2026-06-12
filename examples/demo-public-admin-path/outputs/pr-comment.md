## ChangeGate: BLOCK

**2 risk clusters** from 11 findings: 11 blocking, 0 warnings, 0 suppressed.

### Decision Reasons

- **Production RDS resilience controls disabled:** 2 supporting findings across 1 affected resource
- **Public admin service reaches sensitive data:** 9 supporting findings across 5 affected resources

### Risk Clusters

#### 1. Public admin service reaches sensitive data

- Severity: `critical`
- Confidence: `high`
- Decision: `block`
- Affected resources: 5
- Supporting findings: 9

**Fix:** Remove the public route to the workload or restrict ingress to approved CIDRs.

Rules:

- `AWS_PUBLIC_ADMIN_SERVICE`
- `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`
- `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`

#### 2. Production RDS resilience controls disabled

- Severity: `high`
- Confidence: `high`
- Decision: `block`
- Affected resources: 1
- Supporting findings: 2

**Fix:** Set backup retention to a non-zero period aligned with recovery requirements.

Rules:

- `AWS_RDS_BACKUP_RETENTION_DISABLED_PROD`
- `AWS_RDS_DELETION_PROTECTION_DISABLED_PROD`
