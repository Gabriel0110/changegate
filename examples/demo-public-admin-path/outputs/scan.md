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

- **Production RDS resilience controls disabled:** 2 supporting findings across 1 affected resource
- **Public admin service reaches sensitive data:** 9 supporting findings across 5 affected resources

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
- **Confidence:** high confidence: every step from public entrypoint through workload to sensitive target is backed by explicit plan or cloud-context graph evidence
- **Graph path:** public entrypoint reaches sensitive asset
- **Attack path step:** load balancer is internet exposed
- **Attack path step:** load balancer routes to listener
- **Attack path step:** listener forwards to target group
- **Attack path step:** target group routes to ECS service
- 7 additional evidence items are available in JSON output.

Remediation:

**Primary fix:** Remove the public route to the workload or restrict ingress to approved CIDRs.

Recommended actions:
- Allow sensitive assets only from reviewed workload security groups and roles.
- Remove direct routing from public workloads to sensitive datastores or secrets.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.
- Segment the workload from sensitive data stores and secrets.

Fix options:
- **Break the reachable path** (preferred): Remove one required edge between the public entrypoint, workload, and sensitive asset.
- **Constrain sensitive access**: Allow the sensitive asset only from reviewed private workload identities or security groups.

Review notes:
- Effort: medium
- Downtime risk: low
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Production RDS backup retention disabled

- Rule: `AWS_RDS_BACKUP_RETENTION_DISABLED_PROD`
- Resource: `aws_db_instance.customer`
- Severity: `high`, confidence: `high`
- Fingerprint: `324be933ef4e91da357ff6fb31ec2ac48d104978a1c6150ad08b7e00cf610f53`

Detects production databases with backup retention disabled or reduced to zero.

Evidence:
- **Rule evidence:** production database backup retention is disabled

Remediation:

**Primary fix:** Set backup retention to a non-zero period aligned with recovery requirements.

Recommended actions:
- Apply through the normal database change process.
- Confirm backup windows and retention meet the service recovery objective.
- Set `backup_retention_period` to the required production value.

Fix options:
- **Enable production backup retention** (preferred): Set `backup_retention_period` to an approved non-zero value for the database or cluster.

Review notes:
- Effort: medium
- Downtime risk: high
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Production RDS deletion protection disabled

- Rule: `AWS_RDS_DELETION_PROTECTION_DISABLED_PROD`
- Resource: `aws_db_instance.customer`
- Severity: `high`, confidence: `high`
- Fingerprint: `28b14f10cff186a89f57c31fa7f174f7f510a48939ede5ed994dd7d47ad6048b`

Detects production databases without deletion protection.

Evidence:
- **Rule evidence:** production database deletion protection is disabled

Remediation:

**Primary fix:** Enable deletion protection for production databases.

Recommended actions:
- Keep stateful deletion controls separate from routine configuration changes.
- Only disable deletion protection in a reviewed teardown or migration plan.
- Set `deletion_protection = true` for production databases and clusters.

Fix options:
- **Enable deletion protection** (preferred): Set `deletion_protection = true` before apply.

Review notes:
- Effort: medium
- Downtime risk: high
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Internet-facing ALB routes to admin service

- Rule: `AWS_PUBLIC_ADMIN_SERVICE`
- Resource: `aws_ecs_service.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `e5d0df2f843eb7bf744541ef8250a37a4696f8b821b68b0e5cc24e8e7f4a4249`

Detects public load balancer paths to resources that appear to expose admin surfaces.

Evidence:
- **Rule evidence:** aws_ecs_service.admin: security group applies to resource (security_groups)
- **Rule evidence:** aws_security_group.public: security group allows public ingress (ingress)

Remediation:

**Primary fix:** Remove public routing to the admin service or require private/authenticated access.

Recommended actions:
- Confirm downstream services are not tagged as admin or production unless the exposure is intentional.
- If public access is required, restrict listener security groups to VPN, zero-trust proxy, or allowlisted CIDRs.
- Set the ALB `internal` argument to `true` for private admin services.

Fix options:
- **Make the endpoint private** (preferred): Move the exposed resource behind private networking or an internal load balancer.
- **Restrict ingress**: Keep the endpoint public only for reviewed CIDRs or authenticated edge controls.

Review notes:
- Owner hint: `service=admin`
- Effort: medium
- Downtime risk: medium
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Internet-facing ALB routes to admin service

- Rule: `AWS_PUBLIC_ADMIN_SERVICE`
- Resource: `aws_lb.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `779bda1491490e30caa7b91608a3cfcb972141efa3ba5a7c9326114c017334ca`

Detects public load balancer paths to resources that appear to expose admin surfaces.

Evidence:
- **Rule evidence:** aws_lb.admin: load balancer is internet exposed (scheme)

Remediation:

**Primary fix:** Remove public routing to the admin service or require private/authenticated access.

Recommended actions:
- Confirm downstream services are not tagged as admin or production unless the exposure is intentional.
- If public access is required, restrict listener security groups to VPN, zero-trust proxy, or allowlisted CIDRs.
- Set the ALB `internal` argument to `true` for private admin services.

Fix options:
- **Make the endpoint private** (preferred): Move the exposed resource behind private networking or an internal load balancer.
- **Restrict ingress**: Keep the endpoint public only for reviewed CIDRs or authenticated edge controls.

Patch suggestion: Prefer internal ALB for admin services

```hcl
resource "aws_lb" "admin" {
  internal = true

  # Keep admin listeners reachable only from private subnets or a trusted proxy.
}
```

Review the patch before applying it.

Review notes:
- Owner hint: `service=admin`
- Effort: medium
- Downtime risk: medium
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Internet-facing ALB routes to admin service

- Rule: `AWS_PUBLIC_ADMIN_SERVICE`
- Resource: `aws_lb_listener.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `5359252b1272d809af55898f8f6baaaa72e734d8b7c295f32dc9763c6445e691`

Detects public load balancer paths to resources that appear to expose admin surfaces.

Evidence:
- **Rule evidence:** aws_lb.admin: load balancer is internet exposed (scheme)
- **Rule evidence:** aws_lb_listener.admin: load balancer routes to listener (load_balancer_arn)

Remediation:

**Primary fix:** Remove public routing to the admin service or require private/authenticated access.

Recommended actions:
- Confirm downstream services are not tagged as admin or production unless the exposure is intentional.
- If public access is required, restrict listener security groups to VPN, zero-trust proxy, or allowlisted CIDRs.
- Set the ALB `internal` argument to `true` for private admin services.

Fix options:
- **Make the endpoint private** (preferred): Move the exposed resource behind private networking or an internal load balancer.
- **Restrict ingress**: Keep the endpoint public only for reviewed CIDRs or authenticated edge controls.

Review notes:
- Effort: medium
- Downtime risk: medium
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Internet-facing ALB routes to admin service

- Rule: `AWS_PUBLIC_ADMIN_SERVICE`
- Resource: `aws_lb_target_group.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `e1b57fb5a605ab56ec4be367ed050ecbc6fec7df730c4fa56470c69d63d080e5`

Detects public load balancer paths to resources that appear to expose admin surfaces.

Evidence:
- **Rule evidence:** aws_lb.admin: load balancer is internet exposed (scheme)
- **Rule evidence:** aws_lb_listener.admin: listener forwards to target group (default_action.target_group_arn)
- **Rule evidence:** aws_lb_listener.admin: load balancer routes to listener (load_balancer_arn)

Remediation:

**Primary fix:** Remove public routing to the admin service or require private/authenticated access.

Recommended actions:
- Confirm downstream services are not tagged as admin or production unless the exposure is intentional.
- If public access is required, restrict listener security groups to VPN, zero-trust proxy, or allowlisted CIDRs.
- Set the ALB `internal` argument to `true` for private admin services.

Fix options:
- **Make the endpoint private** (preferred): Move the exposed resource behind private networking or an internal load balancer.
- **Restrict ingress**: Keep the endpoint public only for reviewed CIDRs or authenticated edge controls.

Review notes:
- Effort: medium
- Downtime risk: medium
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Public resource can reach sensitive datastore

- Rule: `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`
- Resource: `aws_ecs_service.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `289677f619f8b5fe649cd1623240356274b6601c243bb018932a7cc607cce994`

Detects public resources that can reach sensitive data stores through the graph.

Evidence:
- **Graph path:** public resource has a high-confidence graph path to sensitive datastore
- **Reachable sensitive asset:** sensitive datastore is reachable from public resource
- **Graph edge:** resource can send traffic through security group
- **Graph edge:** security group applies to resource

Remediation:

**Primary fix:** Break the public-to-sensitive path with private networking, scoped security groups, or service isolation.

Recommended actions:
- Allow datastore access only from reviewed private workload security groups.
- Remove direct routing from public workloads to sensitive datastores.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.

Fix options:
- **Remove datastore reachability** (preferred): Eliminate the route, security-group edge, or identity edge that lets the public path reach the datastore.
- **Allow only private workload access**: Restrict datastore access to reviewed private workload security groups or roles.

Review notes:
- Owner hint: `service=admin`
- Effort: medium
- Downtime risk: low
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Public resource can reach sensitive datastore

- Rule: `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`
- Resource: `aws_lb.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `0bb507a041d1e84e1b42329760a67bc4f19d3d20fd0af0e3fd874e9c4df94c55`

Detects public resources that can reach sensitive data stores through the graph.

Evidence:
- **Graph path:** public resource has a high-confidence graph path to sensitive datastore
- **Reachable sensitive asset:** sensitive datastore is reachable from public resource
- **Graph edge:** load balancer routes to listener
- **Graph edge:** listener forwards to target group
- **Graph edge:** target group routes to ECS service
- **Graph edge:** resource can send traffic through security group
- 1 additional evidence item is available in JSON output.

Remediation:

**Primary fix:** Break the public-to-sensitive path with private networking, scoped security groups, or service isolation.

Recommended actions:
- Allow datastore access only from reviewed private workload security groups.
- Remove direct routing from public workloads to sensitive datastores.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.

Fix options:
- **Remove datastore reachability** (preferred): Eliminate the route, security-group edge, or identity edge that lets the public path reach the datastore.
- **Allow only private workload access**: Restrict datastore access to reviewed private workload security groups or roles.

Review notes:
- Owner hint: `service=admin`
- Effort: medium
- Downtime risk: low
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Public resource can reach sensitive datastore

- Rule: `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`
- Resource: `aws_lb_listener.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `29c87a063ce4eac4199463e770391d5c99add8cf7be6382ca10e8c5b7df777bf`

Detects public resources that can reach sensitive data stores through the graph.

Evidence:
- **Graph path:** public resource has a high-confidence graph path to sensitive datastore
- **Reachable sensitive asset:** sensitive datastore is reachable from public resource
- **Graph edge:** listener forwards to target group
- **Graph edge:** target group routes to ECS service
- **Graph edge:** resource can send traffic through security group
- **Graph edge:** security group applies to resource

Remediation:

**Primary fix:** Break the public-to-sensitive path with private networking, scoped security groups, or service isolation.

Recommended actions:
- Allow datastore access only from reviewed private workload security groups.
- Remove direct routing from public workloads to sensitive datastores.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.

Fix options:
- **Remove datastore reachability** (preferred): Eliminate the route, security-group edge, or identity edge that lets the public path reach the datastore.
- **Allow only private workload access**: Restrict datastore access to reviewed private workload security groups or roles.

Review notes:
- Effort: medium
- Downtime risk: low
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Public resource can reach sensitive datastore

- Rule: `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`
- Resource: `aws_lb_target_group.admin`
- Severity: `high`, confidence: `high`
- Fingerprint: `5a5cf0d48debb217310634556d14e72242d7cb45587188291b6103bd5040f73a`

Detects public resources that can reach sensitive data stores through the graph.

Evidence:
- **Graph path:** public resource has a high-confidence graph path to sensitive datastore
- **Reachable sensitive asset:** sensitive datastore is reachable from public resource
- **Graph edge:** target group routes to ECS service
- **Graph edge:** resource can send traffic through security group
- **Graph edge:** security group applies to resource

Remediation:

**Primary fix:** Break the public-to-sensitive path with private networking, scoped security groups, or service isolation.

Recommended actions:
- Allow datastore access only from reviewed private workload security groups.
- Remove direct routing from public workloads to sensitive datastores.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.

Fix options:
- **Remove datastore reachability** (preferred): Eliminate the route, security-group edge, or identity edge that lets the public path reach the datastore.
- **Allow only private workload access**: Restrict datastore access to reviewed private workload security groups or roles.

Review notes:
- Effort: medium
- Downtime risk: low
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.
