# AWS Architecture Visualization

ChangeGate can turn a redacted AWS context snapshot into a self-contained architecture diagram. This is separate from deployment gating: architecture commands do not evaluate rules, do not return `ALLOW`, `WARN`, or `BLOCK`, and do not require a Terraform/OpenTofu plan.

Architecture diagrams are built from AWS cloud-context inventory, not Terraform source or plan files. ChangeGate uses read-only AWS APIs to collect metadata about resources and relationships, redacts the snapshot, and renders the selected view. See [Cloud Context](cloud-context.md#live-aws-collection) for credential and collection behavior.

```bash
changegate architecture aws visualize \
  --profile readonly \
  --regions us-east-1 \
  --out aws-architecture.html
```

## Create A Snapshot

Use a read-only snapshot when you want a repeatable offline diagram:

```bash
changegate context aws snapshot \
  --out .changegate/aws-context.json \
  --collect=all \
  --regions us-east-1,us-west-2
```

The snapshot is redacted before it is written. Review the generated file before sharing it outside your environment.

## Generate An Interactive Architecture Map

```bash
changegate architecture aws visualize \
  --context-file .changegate/aws-context.json \
  --view account \
  --out aws-architecture.html
```

The default `account` view uses an architecture-map layout: account, region, VPC, subnet, regional services, global services, and resource cards are grouped so the result reads like an AWS environment map instead of a generic dependency graph.

The HTML file is self-contained. It does not load external scripts or call a hosted service. The viewer includes search, role filters, zoom, pan, a minimap, collapsible containers, draggable resource cards and containers, connected-edge highlighting, an inventory list, and a right-side resource inspector.

Click a resource to inspect its identity, placement, properties, tags, and connected relationships. Connected nodes and edges are highlighted so you can quickly see upstream and downstream dependencies.

Use **Save layout** after dragging resources or containers into a useful arrangement. Use **Load layout** to reapply the saved positions in the browser when you reopen or regenerate a comparable diagram.

Use `--layout graph` when you want the lower-level node-link graph instead:

```bash
changegate architecture aws visualize \
  --context-file .changegate/aws-context.json \
  --view account \
  --layout graph \
  --out aws-architecture-graph.html
```

## Views

Use `--view` to keep large environments readable:

| View | Use it for |
| ---- | ---------- |
| `account` | Complete collected topology as a grouped architecture map, capped by `--max-nodes`. |
| `network` | VPCs, subnets, route tables, gateways, load balancers, security groups, and related attachments. |
| `public-exposure` | Internet-reachable resources and downstream paths from public entrypoints. This view uses the graph layout by default because path direction is the main signal. |
| `data` | Sensitive data stores, secrets, KMS keys, and connected workloads or principals. |
| `iam` | IAM roles, policies, trust relationships, permission boundaries, and OIDC relationships. |
| `compute` | EC2, ECS, Lambda, EKS, and directly connected network, data, and IAM resources. |
| `resource` | A local neighborhood around a single resource address, ARN, or ID. |

Examples:

```bash
changegate architecture aws visualize \
  --context-file .changegate/aws-context.json \
  --view public-exposure \
  --out public-exposure.html

changegate architecture aws visualize \
  --context-file .changegate/aws-context.json \
  --view public-exposure \
  --layout map \
  --out public-exposure-map.html

changegate architecture aws visualize \
  --context-file .changegate/aws-context.json \
  --view data \
  --out data-architecture.html

changegate architecture aws visualize \
  --context-file .changegate/aws-context.json \
  --view resource \
  --resource arn:aws:lambda:us-east-1:123456789012:function:api \
  --out lambda-neighborhood.html
```

## Export Diagram Source

Export machine-readable graph JSON or renderable diagram source:

```bash
changegate architecture aws export \
  --context-file .changegate/aws-context.json \
  --view network \
  --format json \
  --out aws-network.json

changegate architecture aws export \
  --context-file .changegate/aws-context.json \
  --view network \
  --format mermaid \
  --out aws-network.mmd

changegate architecture aws export \
  --context-file .changegate/aws-context.json \
  --view public-exposure \
  --format dot \
  --out public-exposure.dot
```

If Graphviz is installed, render SVG, PNG, or PDF directly:

```bash
changegate architecture aws render \
  --context-file .changegate/aws-context.json \
  --view network \
  --render-format svg \
  --out aws-network.svg
```

## Compare Two Snapshots

Use `diff` when you want to compare two saved snapshots before opening a full diagram:

```bash
changegate architecture aws diff \
  --before-context-file .changegate/aws-context-before.json \
  --after-context-file .changegate/aws-context-after.json \
  --view account
```

The diff reports added, removed, and changed resources plus added or removed relationships for the selected view. Use `--format json` when you want to feed the diff into another review tool.

## Live Read-Only Collection

You can collect and render in one command. When no `--context-file` is supplied, architecture commands default to `--collect=all`:

```bash
changegate architecture aws visualize \
  --regions us-east-1 \
  --profile readonly \
  --view account \
  --out aws-architecture.html
```

Use `--collect` when you want narrower collection:

```bash
changegate architecture aws visualize \
  --collect=network,edge \
  --regions us-east-1 \
  --view public-exposure \
  --out public-exposure.html
```

Supported collection groups are:

| Group | Collects |
| ----- | -------- |
| `all` | Identity, network, edge, IAM, compute, and data metadata. This is the default for architecture commands without `--context-file`. |
| `identity` | Caller/account metadata and enabled-region discovery. |
| `network` | VPCs, subnets, route tables, gateways, security groups, and network interfaces. |
| `edge` | Load balancers, listeners, target groups, CloudFront, API Gateway, and Lambda Function URLs. |
| `iam` | Roles, trust policies, policy shapes, permission boundaries, instance profiles, and OIDC providers. |
| `compute` | EC2, ECS, Lambda, EKS, task definitions, roles, and workload relationships. |
| `data` | RDS, S3, Secrets Manager, KMS, OpenSearch, ElastiCache, and EFS metadata. |

For repeatability, prefer creating a snapshot first and visualizing the saved file.

## Large Accounts

Architecture diagrams are capped by `--max-nodes` to keep the output usable:

```bash
changegate architecture aws visualize \
  --context-file .changegate/aws-context.json \
  --view account \
  --max-nodes 500 \
  --out aws-architecture.html
```

For large accounts, start with focused views such as `network`, `public-exposure`, `data`, `iam`, or `resource`.

## Summary

```bash
changegate architecture aws summary \
  --context-file .changegate/aws-context.json \
  --view account
```

The summary reports node and edge counts, public resources, sensitive assets, snapshot diagnostics, and whether the selected view was truncated.
