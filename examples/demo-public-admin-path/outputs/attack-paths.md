# Attack Paths

## Public entrypoint aws_lb.admin reaches sensitive asset aws_db_instance.customer

- ID: `attack-path-809c77cb5de3cd2d`
- Type: `public_to_sensitive_data`
- Kind: `network`
- Decision: `block`
- Severity: `critical`
- Confidence: `high`
- Confidence reason: path confidence is based on plan graph evidence
- Source: `plan`
- Finding rules: `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`
- Entrypoint: `aws_lb.admin`
- Target: `aws_db_instance.customer`

Affected resources:

- `aws_db_instance.customer` `sensitive_asset` `aws_db_instance`
- `aws_ecs_service.admin` `intermediate` `aws_ecs_service`
- `aws_lb.admin` `entrypoint` `aws_lb`
- `aws_lb_listener.admin` `intermediate` `aws_lb_listener`
- `aws_lb_target_group.admin` `intermediate` `aws_lb_target_group`
- `aws_security_group.public` `intermediate` `aws_security_group`
- `internet` `intermediate`

Steps:

1. `internet` -> `aws_lb.admin` via `has_public_access` (`plan/high`): load balancer is internet exposed
1. `aws_lb.admin` -> `aws_lb_listener.admin` via `routes_to` (`plan/high`): load balancer routes to listener
1. `aws_lb_listener.admin` -> `aws_lb_target_group.admin` via `routes_to` (`plan/high`): listener forwards to target group
1. `aws_lb_target_group.admin` -> `aws_ecs_service.admin` via `routes_to` (`plan/high`): target group routes to ECS service
1. `aws_ecs_service.admin` -> `aws_security_group.public` via `allows_egress` (`plan/high`): resource can send traffic through security group
1. `aws_security_group.public` -> `aws_db_instance.customer` via `allows_ingress` (`plan/high`): security group applies to resource

Mitigations:

- Remove the public route to the workload or restrict ingress to approved CIDRs.
- Segment the workload from sensitive data stores and secrets.

References:

- docs/attack-paths.md
