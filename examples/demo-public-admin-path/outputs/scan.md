# ChangeGate: BLOCK

| Metric | Value |
| --- | ---: |
| Risk clusters | 2 |
| Findings | 11 |
| Blocking | 11 |
| Warnings | 0 |
| Suppressed | 0 |
| Downgraded | 0 |
| Graph nodes | 7 |
| Graph edges | 12 |

## Decision reasons

- `MEETS_BLOCK_THRESHOLD` `Production RDS resilience controls disabled`: Production RDS resilience controls disabled: 2 supporting findings across 1 affected resources
- `MEETS_BLOCK_THRESHOLD` `Public admin service reaches sensitive data`: Public admin service reaches sensitive data: 9 supporting findings across 5 affected resources

## Risk clusters

### Public admin service reaches sensitive data

- Decision: `block`
- Severity: `critical`, confidence: `high`
- Affected resources: 5
- Supporting findings: 9
- Rules: `AWS_PUBLIC_ADMIN_SERVICE`, `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`, `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`
- Primary fix: Remove the public route to the workload or restrict ingress to approved CIDRs.
- Resources: `aws_db_instance.customer`, `aws_ecs_service.admin`, `aws_lb.admin`, `aws_lb_listener.admin`, `aws_lb_target_group.admin`

### Production RDS resilience controls disabled

- Decision: `block`
- Severity: `high`, confidence: `high`
- Affected resources: 1
- Supporting findings: 2
- Rules: `AWS_RDS_BACKUP_RETENTION_DISABLED_PROD`, `AWS_RDS_DELETION_PROTECTION_DISABLED_PROD`
- Primary fix: Set backup retention to a non-zero period aligned with recovery requirements.
- Resources: `aws_db_instance.customer`

## Finding details

### Public entrypoint aws_lb.admin reaches sensitive asset aws_db_instance.customer

- Rule: `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`
- Resource: `aws_db_instance.customer`
- Severity: `critical`, confidence: `high`
- Fingerprint: `a804d099c2d70442b3d0db2c830ec5a10aa2365a6d56cd467d3782815c790907`

ChangeGate detected a high-signal infrastructure attack path.

Evidence:
- `attack_path` `attack_path.id`: attack path attack-path-809c77cb5de3cd2d produced block decision
- `attack_path` `attack_path.type`: attack path type is public_to_sensitive_data
- `attack_path` `attack_path.kind`: attack path kind is network
- `attack_path` `attack_path.confidence_reason`: path confidence is based on plan graph evidence
- `attack_path.graph_path` `graph.path`: public entrypoint reaches sensitive asset
- `attack_path` `attack_path.source`: attack path source is plan
- `attack_path` `attack_path.affected_resources`: attack path affected resources are linked to this finding
- `attack_path.step` `has_public_access`: load balancer is internet exposed
- `attack_path.step` `routes_to`: load balancer routes to listener
- `attack_path.step` `routes_to`: listener forwards to target group
- `attack_path.step` `routes_to`: target group routes to ECS service
- `attack_path.step` `allows_egress`: resource can send traffic through security group
- `attack_path.step` `allows_ingress`: security group applies to resource

Remediation:
- Remove the public route to the workload or restrict ingress to approved CIDRs.
- Allow sensitive assets only from reviewed workload security groups and roles.
- Remove direct routing from public workloads to sensitive datastores or secrets.
- Remove the public route to the workload or restrict ingress to approved CIDRs.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.
- Segment the workload from sensitive data stores and secrets.
- Why this works: Removing any required step breaks the attack path before deployment.
- Fix confidence: `medium`
- Automatic patch: `false`
- Patch suggestion: Attack path requires topology review (ChangeGate does not auto-patch multi-resource attack paths because the correct fix depends on service ownership, routing intent, and approved access patterns.)
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Production RDS backup retention disabled

- Rule: `AWS_RDS_BACKUP_RETENTION_DISABLED_PROD`
- Resource: `aws_db_instance.customer`
- Severity: `high`, confidence: `high`
- Fingerprint: `324be933ef4e91da357ff6fb31ec2ac48d104978a1c6150ad08b7e00cf610f53`

Detects production databases with backup retention disabled or reduced to zero.

Evidence:
- `rule` `backup_retention_period`: production database backup retention is disabled

Remediation:
- Set backup retention to a non-zero period aligned with recovery requirements.
- Confirm the planned delete or replacement is intentional.
- Enable deletion protection where supported.
- Take a backup or snapshot and document rollback.
- Why this works: Availability controls reduce the chance that a routine apply becomes an outage or data-loss event.
- Fix confidence: `medium`
- Automatic patch: `false`
- Patch suggestion: Availability changes require review (ChangeGate does not auto-patch destructive or downtime-prone changes because the safe path depends on service ownership and recovery requirements.)
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Production RDS deletion protection disabled

- Rule: `AWS_RDS_DELETION_PROTECTION_DISABLED_PROD`
- Resource: `aws_db_instance.customer`
- Severity: `high`, confidence: `high`
- Fingerprint: `28b14f10cff186a89f57c31fa7f174f7f510a48939ede5ed994dd7d47ad6048b`

Detects production databases without deletion protection.

Evidence:
- `rule` `deletion_protection`: production database deletion protection is disabled

Remediation:
- Enable deletion protection for production databases.
- Confirm the planned delete or replacement is intentional.
- Enable deletion protection where supported.
- Take a backup or snapshot and document rollback.
- Why this works: Availability controls reduce the chance that a routine apply becomes an outage or data-loss event.
- Fix confidence: `medium`
- Automatic patch: `false`
- Patch suggestion: Availability changes require review (ChangeGate does not auto-patch destructive or downtime-prone changes because the safe path depends on service ownership and recovery requirements.)
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Internet-facing ALB routes to admin service

- Rule: `AWS_PUBLIC_ADMIN_SERVICE`
- Resource: `aws_ecs_service.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `e5d0df2f843eb7bf744541ef8250a37a4696f8b821b68b0e5cc24e8e7f4a4249`

Detects public load balancer paths to resources that appear to expose admin surfaces.

Evidence:
- `rule` `graph`: aws_ecs_service.admin: security group applies to resource (security_groups)
- `rule` `graph`: aws_security_group.public: security group allows public ingress (ingress)

Remediation:
- Remove public routing to the admin service or require private/authenticated access.
- Confirm downstream services are not tagged as admin or production unless the exposure is intentional.
- If public access is required, restrict listener security groups to VPN, zero-trust proxy, or allowlisted CIDRs.
- Set the ALB `internal` argument to `true` for private admin services.
- Why this works: Removing direct public routing to admin workloads prevents unauthenticated internet clients from reaching privileged control surfaces.
- Fix confidence: `high`
- Automatic patch: `false`

Patch suggestion: Prefer internal ALB for admin services

```hcl
resource "aws_lb" "admin" {
  internal = true

  # Keep admin listeners reachable only from private subnets or a trusted proxy.
}
```
- Owner hints: `service=admin`
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Internet-facing ALB routes to admin service

- Rule: `AWS_PUBLIC_ADMIN_SERVICE`
- Resource: `aws_lb.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `779bda1491490e30caa7b91608a3cfcb972141efa3ba5a7c9326114c017334ca`

Detects public load balancer paths to resources that appear to expose admin surfaces.

Evidence:
- `rule` `graph`: aws_lb.admin: load balancer is internet exposed (scheme)

Remediation:
- Remove public routing to the admin service or require private/authenticated access.
- Confirm downstream services are not tagged as admin or production unless the exposure is intentional.
- If public access is required, restrict listener security groups to VPN, zero-trust proxy, or allowlisted CIDRs.
- Set the ALB `internal` argument to `true` for private admin services.
- Why this works: Removing direct public routing to admin workloads prevents unauthenticated internet clients from reaching privileged control surfaces.
- Fix confidence: `high`
- Automatic patch: `false`

Patch suggestion: Prefer internal ALB for admin services

```hcl
resource "aws_lb" "admin" {
  internal = true

  # Keep admin listeners reachable only from private subnets or a trusted proxy.
}
```
- Owner hints: `service=admin`
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Internet-facing ALB routes to admin service

- Rule: `AWS_PUBLIC_ADMIN_SERVICE`
- Resource: `aws_lb_listener.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `5359252b1272d809af55898f8f6baaaa72e734d8b7c295f32dc9763c6445e691`

Detects public load balancer paths to resources that appear to expose admin surfaces.

Evidence:
- `rule` `graph`: aws_lb.admin: load balancer is internet exposed (scheme)
- `rule` `graph`: aws_lb_listener.admin: load balancer routes to listener (load_balancer_arn)

Remediation:
- Remove public routing to the admin service or require private/authenticated access.
- Confirm downstream services are not tagged as admin or production unless the exposure is intentional.
- If public access is required, restrict listener security groups to VPN, zero-trust proxy, or allowlisted CIDRs.
- Set the ALB `internal` argument to `true` for private admin services.
- Why this works: Removing direct public routing to admin workloads prevents unauthenticated internet clients from reaching privileged control surfaces.
- Fix confidence: `high`
- Automatic patch: `false`

Patch suggestion: Prefer internal ALB for admin services

```hcl
resource "aws_lb" "admin" {
  internal = true

  # Keep admin listeners reachable only from private subnets or a trusted proxy.
}
```
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Internet-facing ALB routes to admin service

- Rule: `AWS_PUBLIC_ADMIN_SERVICE`
- Resource: `aws_lb_target_group.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `e1b57fb5a605ab56ec4be367ed050ecbc6fec7df730c4fa56470c69d63d080e5`

Detects public load balancer paths to resources that appear to expose admin surfaces.

Evidence:
- `rule` `graph`: aws_lb.admin: load balancer is internet exposed (scheme)
- `rule` `graph`: aws_lb_listener.admin: listener forwards to target group (default_action.target_group_arn)
- `rule` `graph`: aws_lb_listener.admin: load balancer routes to listener (load_balancer_arn)

Remediation:
- Remove public routing to the admin service or require private/authenticated access.
- Confirm downstream services are not tagged as admin or production unless the exposure is intentional.
- If public access is required, restrict listener security groups to VPN, zero-trust proxy, or allowlisted CIDRs.
- Set the ALB `internal` argument to `true` for private admin services.
- Why this works: Removing direct public routing to admin workloads prevents unauthenticated internet clients from reaching privileged control surfaces.
- Fix confidence: `high`
- Automatic patch: `false`

Patch suggestion: Prefer internal ALB for admin services

```hcl
resource "aws_lb" "admin" {
  internal = true

  # Keep admin listeners reachable only from private subnets or a trusted proxy.
}
```
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Public resource can reach sensitive datastore

- Rule: `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`
- Resource: `aws_ecs_service.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `289677f619f8b5fe649cd1623240356274b6601c243bb018932a7cc607cce994`

Detects public resources that can reach sensitive data stores through the graph.

Evidence:
- `rule` `graph.path`: public resource has a high-confidence graph path to sensitive datastore
- `rule` `graph.target`: sensitive datastore is reachable from public resource
- `rule` `graph.edge`: resource can send traffic through security group
- `rule` `graph.edge`: security group applies to resource

Remediation:
- Break the public-to-sensitive path with private networking, scoped security groups, or service isolation.
- Allow datastore access only from reviewed private workload security groups.
- Remove direct routing from public workloads to sensitive datastores.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.
- Why this works: The datastore is reachable only while each graph edge remains in place; removing public exposure, routing, or datastore access breaks the path.
- Fix confidence: `medium`
- Automatic patch: `false`
- Patch suggestion: Datastore reachability requires topology review (ChangeGate does not auto-patch public-to-datastore paths because the correct fix depends on service ownership, routing intent, security groups, and approved access patterns.)
- Owner hints: `service=admin`
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Public resource can reach sensitive datastore

- Rule: `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`
- Resource: `aws_lb.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `0bb507a041d1e84e1b42329760a67bc4f19d3d20fd0af0e3fd874e9c4df94c55`

Detects public resources that can reach sensitive data stores through the graph.

Evidence:
- `rule` `graph.path`: public resource has a high-confidence graph path to sensitive datastore
- `rule` `graph.target`: sensitive datastore is reachable from public resource
- `rule` `graph.edge`: load balancer routes to listener
- `rule` `graph.edge`: listener forwards to target group
- `rule` `graph.edge`: target group routes to ECS service
- `rule` `graph.edge`: resource can send traffic through security group
- `rule` `graph.edge`: security group applies to resource

Remediation:
- Break the public-to-sensitive path with private networking, scoped security groups, or service isolation.
- Allow datastore access only from reviewed private workload security groups.
- Remove direct routing from public workloads to sensitive datastores.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.
- Why this works: The datastore is reachable only while each graph edge remains in place; removing public exposure, routing, or datastore access breaks the path.
- Fix confidence: `medium`
- Automatic patch: `false`
- Patch suggestion: Datastore reachability requires topology review (ChangeGate does not auto-patch public-to-datastore paths because the correct fix depends on service ownership, routing intent, security groups, and approved access patterns.)
- Owner hints: `service=admin`
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Public resource can reach sensitive datastore

- Rule: `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`
- Resource: `aws_lb_listener.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `29c87a063ce4eac4199463e770391d5c99add8cf7be6382ca10e8c5b7df777bf`

Detects public resources that can reach sensitive data stores through the graph.

Evidence:
- `rule` `graph.path`: public resource has a high-confidence graph path to sensitive datastore
- `rule` `graph.target`: sensitive datastore is reachable from public resource
- `rule` `graph.edge`: listener forwards to target group
- `rule` `graph.edge`: target group routes to ECS service
- `rule` `graph.edge`: resource can send traffic through security group
- `rule` `graph.edge`: security group applies to resource

Remediation:
- Break the public-to-sensitive path with private networking, scoped security groups, or service isolation.
- Allow datastore access only from reviewed private workload security groups.
- Remove direct routing from public workloads to sensitive datastores.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.
- Why this works: The datastore is reachable only while each graph edge remains in place; removing public exposure, routing, or datastore access breaks the path.
- Fix confidence: `medium`
- Automatic patch: `false`
- Patch suggestion: Datastore reachability requires topology review (ChangeGate does not auto-patch public-to-datastore paths because the correct fix depends on service ownership, routing intent, security groups, and approved access patterns.)
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Public resource can reach sensitive datastore

- Rule: `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`
- Resource: `aws_lb_target_group.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `5a5cf0d48debb217310634556d14e72242d7cb45587188291b6103bd5040f73a`

Detects public resources that can reach sensitive data stores through the graph.

Evidence:
- `rule` `graph.path`: public resource has a high-confidence graph path to sensitive datastore
- `rule` `graph.target`: sensitive datastore is reachable from public resource
- `rule` `graph.edge`: target group routes to ECS service
- `rule` `graph.edge`: resource can send traffic through security group
- `rule` `graph.edge`: security group applies to resource

Remediation:
- Break the public-to-sensitive path with private networking, scoped security groups, or service isolation.
- Allow datastore access only from reviewed private workload security groups.
- Remove direct routing from public workloads to sensitive datastores.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.
- Why this works: The datastore is reachable only while each graph edge remains in place; removing public exposure, routing, or datastore access breaks the path.
- Fix confidence: `medium`
- Automatic patch: `false`
- Patch suggestion: Datastore reachability requires topology review (ChangeGate does not auto-patch public-to-datastore paths because the correct fix depends on service ownership, routing intent, security groups, and approved access patterns.)
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.

