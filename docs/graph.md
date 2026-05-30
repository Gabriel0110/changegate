# Blast-Radius Graph

ChangeGate builds a deterministic resource graph from Terraform/OpenTofu plan JSON. The graph is used by built-in rules, impact statements, and Review Intelligence commands.

## Graph v2 Core

Graph v2 adds first-class security classification for nodes:

* `public_entrypoint`
* `workload`
* `data_store`
* `secret`
* `kms_key`
* `principal`
* `policy`
* `network_boundary`
* `unknown`

Graph v2 also adds richer relationship edges, including routing, ingress, egress, attachment, role assumption, pass-role, permission grants, secret reads, KMS encryption, writes, replication, and protective controls.

## Query Model

The internal graph API supports:

* exposure checks for a resource
* deterministic path extraction with depth and count limits
* blast-radius summaries from a resource
* public entrypoint enumeration
* sensitive asset enumeration
* changed public-to-sensitive boundary crossings

The next tranche exposes these APIs through `changegate graph` commands. Until then, they are available to rules, impact rendering, and tests.

## AWS Coverage

Graph v2 classifies and connects common AWS resources where plan data is sufficient:

* ALB/NLB/ELB, listeners, target groups, CloudFront, and API Gateway
* ECS services, task definitions, Lambda functions, EC2 instances, EKS clusters, and node groups
* security groups, subnets, route tables, routes, internet gateways, NAT gateways, VPC peering, and transit gateway routes
* RDS/Aurora, S3, DynamoDB, EFS, OpenSearch, ElastiCache, Secrets Manager, and KMS
* IAM roles, users, groups, policies, inline policies, attachments, trust policies, and instance profiles

Unknown resources are still represented as graph nodes so the graph remains tolerant of new provider resources and partial plan data.
