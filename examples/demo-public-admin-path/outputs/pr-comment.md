## ChangeGate: BLOCK

**11 findings**: 11 blocking, 0 warnings, 0 suppressed.

**Decision reasons**
- `MEETS_BLOCK_THRESHOLD` `aws_db_instance.customer`: attack path attack-path-809c77cb5de3cd2d meets critical/high threshold
- `MEETS_BLOCK_THRESHOLD` `aws_db_instance.customer`: finding meets block threshold
- `MEETS_BLOCK_THRESHOLD` `aws_db_instance.customer`: finding meets block threshold
- ... 8 more reasons

**Top findings**
- `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH` `critical/high` Public entrypoint aws_lb.admin reaches sensitive asset aws_db_instance.customer on `aws_db_instance.customer`
  Fix: Remove the public route to the workload or restrict ingress to approved CIDRs.
  Why: Removing any required step breaks the attack path before deployment.
- `AWS_RDS_BACKUP_RETENTION_DISABLED_PROD` `high/high` Production RDS backup retention disabled on `aws_db_instance.customer`
  Fix: Set backup retention to a non-zero period aligned with recovery requirements.
  Why: Availability controls reduce the chance that a routine apply becomes an outage or data-loss event.
- `AWS_RDS_DELETION_PROTECTION_DISABLED_PROD` `high/high` Production RDS deletion protection disabled on `aws_db_instance.customer`
  Fix: Enable deletion protection for production databases.
  Why: Availability controls reduce the chance that a routine apply becomes an outage or data-loss event.
- ... 8 more findings
