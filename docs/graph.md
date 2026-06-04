# Blast-Radius Graph

ChangeGate builds a deterministic resource graph from Terraform/OpenTofu plan JSON. The graph is used by built-in rules, impact statements, and Review Intelligence commands.

## Graph v2 Core

Graph v2 adds first-class security classification for nodes:

- `public_entrypoint`
- `workload`
- `data_store`
- `secret`
- `kms_key`
- `principal`
- `policy`
- `network_boundary`
- `unknown`

Graph v2 also adds richer relationship edges, including routing, ingress, egress, attachment, role assumption, pass-role, permission grants, secret reads, KMS encryption, writes, replication, and protective controls. Every edge can carry `source` and `confidence` so path output can distinguish plan-derived relationships from optional live cloud-context relationships.

Graph v2 is the supported graph contract. If you have older graph JSON artifacts, create fresh graph output with the current CLI.

## Query Model

Graph commands support:

- exposure checks for a resource
- deterministic path extraction with depth and count limits
- blast-radius summaries from a resource
- public entrypoint enumeration
- sensitive asset enumeration
- changed public-to-sensitive boundary crossings

These APIs are exposed through:

```bash
changegate graph summary --plan tfplan.json
changegate graph path --plan tfplan.json --from aws_lb.admin --to aws_db_instance.customer
changegate graph exposure --plan tfplan.json --resource aws_ecs_service.admin
changegate graph export --plan tfplan.json --format json
changegate graph export --plan tfplan.json --format dot --out graph.dot
changegate graph path --plan tfplan.json --from aws_lb.admin --to aws_db_instance.customer --format mermaid --out graph-path.mmd
changegate graph visualize --plan tfplan.json --out graph.html
changegate graph visualize --plan tfplan.json --view path --from aws_lb.admin --to aws_db_instance.customer --out graph-path.html
changegate graph visualize --plan tfplan.json --view exposure --resource aws_ecs_service.admin --out exposure.html
changegate graph render --plan tfplan.json --view exposure --resource aws_ecs_service.admin --render-format svg --out exposure.svg
```

`summary`, `path`, and `exposure` render human-readable output by default and support `--format json` for automation. The graph commands also support `--format dot` and `--format mermaid` for renderable diagram source. `export` writes the full graph as JSON, DOT, or Mermaid.

`graph visualize` writes a dependency-free HTML file with an interactive SVG graph, search, role filters, highlighted paths, and a node evidence inspector. It is the recommended artifact when reviewers need to understand blast radius without reading JSON. The HTML is self-contained and does not load external scripts.

`graph render` is an optional convenience wrapper around Graphviz `dot`. It renders the same DOT model to SVG, PNG, or PDF and requires Graphviz to be installed on the machine running ChangeGate. If Graphviz is not available, use `--format dot` or `graph visualize`.

Scan, review, and impact commands merge cloud context into the graph when `--context-file` or `--cloud-context aws` is supplied. The merge preserves provenance:

- `source: plan` for Terraform/OpenTofu plan relationships.
- `source: cloud_context` for live AWS snapshot relationships.
- `metadata.sources: plan,cloud_context` when both inputs support the same relationship.

Cloud context can add live-only attachments, public exposure edges, sensitive-data relationships, and IAM relationships. Conflict diagnostics are emitted when live context materially contradicts the plan graph, such as a resource that the plan graph treats as private but live AWS reports as public.

`graph export` emits the canonical v2 artifact documented by [`schemas/changegate-graph.schema.json`](../schemas/changegate-graph.schema.json):

```json
{
  "version": 2,
  "nodes": {
    "aws_lb.admin": {
      "id": "aws_lb.admin",
      "address": "aws_lb.admin",
      "type": "aws_lb",
      "kind": "public_entrypoint",
      "name": "admin"
    }
  },
  "edges": [
    {
      "from": "internet",
      "to": "aws_lb.admin",
      "type": "routes_to",
      "source": "plan",
      "confidence": "high"
    }
  ]
}
```

## AWS Coverage

Graph v2 classifies and connects common AWS resources where plan data is sufficient:

- ALB/NLB/ELB, listeners, target groups, CloudFront, API Gateway, API Gateway integrations, and Lambda Function URLs
- ECS services, task definitions, Lambda functions, EC2 instances, EKS clusters, and node groups
- security groups, subnets, route tables, routes, internet gateways, NAT gateways, VPC peering, and transit gateway routes
- RDS/Aurora, S3, DynamoDB, EFS, OpenSearch, ElastiCache, Secrets Manager, and KMS
- IAM roles, users, groups, policies, inline policies, attachments, trust policies, instance profiles, Lambda secret references, and KMS relationships

Unknown resources are still represented as graph nodes so the graph remains tolerant of new provider resources and partial plan data.
