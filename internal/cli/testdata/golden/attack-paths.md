# Attack Paths

## Public entrypoint aws_lb.admin reaches sensitive asset aws_db_instance.customer

- ID: `attack-path-ebb91706401c9280`
- Type: `public_to_sensitive_data`
- Decision: `block`
- Severity: `critical`
- Confidence: `high`
- Entrypoint: `aws_lb.admin`
- Target: `aws_db_instance.customer`

Steps:
1. `internet` -> `aws_lb.admin` via `has_public_access`: load balancer is internet exposed
1. `aws_lb.admin` -> `aws_lb_listener.admin` via `routes_to`: load balancer routes to listener
1. `aws_lb_listener.admin` -> `aws_lb_target_group.admin` via `routes_to`: listener forwards to target group
1. `aws_lb_target_group.admin` -> `aws_ecs_service.admin` via `routes_to`: target group routes to ECS service
1. `aws_ecs_service.admin` -> `aws_security_group.public` via `allows_egress`: resource can send traffic through security group
1. `aws_security_group.public` -> `aws_db_instance.customer` via `allows_ingress`: security group applies to resource

Mitigations:
- Remove the public route to the workload or restrict ingress to approved CIDRs.
- Segment the workload from sensitive data stores and secrets.

References:
- https://changegate.dev/docs/attack-paths

