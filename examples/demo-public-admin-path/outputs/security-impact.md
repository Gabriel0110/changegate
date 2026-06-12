# Security Impact Statement

Decision: BLOCK
Review required: Yes

This change introduces:
- 4 public entrypoints
- 5 sensitive assets touched
- 0 IAM permission changes
- 4 network path changes
- 5 data path changes
- 0 active waivers

## Risk Clusters

- `critical/high` Public admin service reaches sensitive data
  - Decision: `block`
  - Affected resources: 5
  - Supporting findings: 9
  - Primary fix: Remove the public route to the workload or restrict ingress to approved CIDRs.
- `high/high` Production RDS resilience controls disabled
  - Decision: `block`
  - Affected resources: 1
  - Supporting findings: 2
  - Primary fix: Set backup retention to a non-zero period aligned with recovery requirements.

## Risk Movement

| Metric | Count |
| --- | ---: |
| New critical risks | 1 |
| New high risks | 10 |
| New medium risks | 0 |
| Existing unchanged risks | 0 |
| Existing worsened risks | 0 |
| Existing improved risks | 0 |
| Resolved high risks | 0 |

## Top Graph Paths

- `aws_db_instance.customer`: internet -> aws_lb.admin -> aws_lb_listener.admin -> aws_lb_target_group.admin -> aws_ecs_service.admin -> aws_security_group.public -> aws_db_instance.customer

## Attack Paths

- `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH` `critical/high` `block` Public entrypoint aws_lb.admin reaches sensitive asset aws_db_instance.customer
  - Confidence reason: high confidence: every step from public entrypoint through workload to sensitive target is backed by explicit plan or cloud-context graph evidence
  - Path: internet -> aws_lb.admin -> aws_lb_listener.admin -> aws_lb_target_group.admin -> aws_ecs_service.admin -> aws_security_group.public -> aws_db_instance.customer

## Top Findings

- `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH` `critical/high` Public entrypoint aws_lb.admin reaches sensitive asset aws_db_instance.customer on `aws_db_instance.customer`
- `AWS_RDS_BACKUP_RETENTION_DISABLED_PROD` `high/high` Production RDS backup retention disabled on `aws_db_instance.customer`
- `AWS_RDS_DELETION_PROTECTION_DISABLED_PROD` `high/high` Production RDS deletion protection disabled on `aws_db_instance.customer`
- `AWS_PUBLIC_ADMIN_SERVICE` `high/high` Internet-facing ALB routes to admin service on `aws_ecs_service.admin`
- `AWS_PUBLIC_TO_SENSITIVE_DATASTORE` `high/high` Public resource can reach sensitive datastore on `aws_ecs_service.admin`
- `AWS_PUBLIC_ADMIN_SERVICE` `high/high` Internet-facing ALB routes to admin service on `aws_lb.admin`
- `AWS_PUBLIC_TO_SENSITIVE_DATASTORE` `high/high` Public resource can reach sensitive datastore on `aws_lb.admin`
- `AWS_PUBLIC_ADMIN_SERVICE` `high/high` Internet-facing ALB routes to admin service on `aws_lb_listener.admin`
- `AWS_PUBLIC_TO_SENSITIVE_DATASTORE` `high/high` Public resource can reach sensitive datastore on `aws_lb_listener.admin`
- `AWS_PUBLIC_ADMIN_SERVICE` `high/high` Internet-facing ALB routes to admin service on `aws_lb_target_group.admin`

## Required Review

- `security`: deployment decision is block
- `data-owner`: sensitive asset is affected
