## ChangeGate: BLOCK

**2 risk clusters** from 11 findings: 11 blocking, 0 warnings, 0 suppressed.

**Decision reasons**
- `MEETS_BLOCK_THRESHOLD` `Production RDS resilience controls disabled`: Production RDS resilience controls disabled: 2 supporting findings across 1 affected resources
- `MEETS_BLOCK_THRESHOLD` `Public admin service reaches sensitive data`: Public admin service reaches sensitive data: 9 supporting findings across 5 affected resources

**Risk clusters**
- `critical/high` Public admin service reaches sensitive data (5 resources, 9 findings)
  Fix: Remove the public route to the workload or restrict ingress to approved CIDRs.
  Rules: `AWS_PUBLIC_ADMIN_SERVICE`, `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`, `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`
- `high/high` Production RDS resilience controls disabled (1 resources, 2 findings)
  Fix: Set backup retention to a non-zero period aligned with recovery requirements.
  Rules: `AWS_RDS_BACKUP_RETENTION_DISABLED_PROD`, `AWS_RDS_DELETION_PROTECTION_DISABLED_PROD`
