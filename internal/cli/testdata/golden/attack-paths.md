# Attack Paths

## Public entrypoint aws_lb.admin reaches sensitive asset aws_db_instance.customer

- Decision: `block`
- Severity: `critical`, confidence: `high`
- Confidence reason: high confidence: every step from public entrypoint through workload to sensitive target is backed by explicit plan or cloud-context graph evidence
- Finding rules: `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`
- Entrypoint: `aws_lb.admin`
- Target: `aws_db_instance.customer`

Affected resources:
- **Sensitive Asset:** `aws_db_instance.customer` (`aws_db_instance`)
- **Intermediate:** `aws_ecs_service.admin` (`aws_ecs_service`)
- **Entrypoint:** `aws_lb.admin` (`aws_lb`)
- **Intermediate:** `aws_lb_listener.admin` (`aws_lb_listener`)
- **Intermediate:** `aws_lb_target_group.admin` (`aws_lb_target_group`)
- **Intermediate:** `aws_security_group.public` (`aws_security_group`)
- **Intermediate:** `internet`

Steps:
1. `internet` -> `aws_lb.admin` via Has Public Access: load balancer is internet exposed
1. `aws_lb.admin` -> `aws_lb_listener.admin` via Routes To: load balancer routes to listener
1. `aws_lb_listener.admin` -> `aws_lb_target_group.admin` via Routes To: listener forwards to target group
1. `aws_lb_target_group.admin` -> `aws_ecs_service.admin` via Routes To: target group routes to ECS service
1. `aws_ecs_service.admin` -> `aws_security_group.public` via Allows Egress: resource can send traffic through security group
1. `aws_security_group.public` -> `aws_db_instance.customer` via Allows Ingress: security group applies to resource

Mitigations:
- Remove the public route to the workload or restrict ingress to approved CIDRs.
- Segment the workload from sensitive data stores and secrets.

References:
- https://github.com/Gabriel0110/changegate/blob/main/docs/attack-paths.md
