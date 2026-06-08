# Cloud Context

ChangeGate is credential-free and offline by default. Cloud context is explicitly opt-in and can be provided through an offline snapshot:

```bash
changegate context aws snapshot --out .changegate/aws-context.json
changegate scan --plan tfplan.json --context-file .changegate/aws-context.json
```

To collect real read-only AWS context, opt in with `--collect`:

```bash
changegate context aws snapshot --out .changegate/aws-context.json --collect
changegate context aws snapshot --out .changegate/aws-context.json --collect network,edge,iam,compute,data --regions us-east-1,us-west-2 --profile prod-readonly
```

Or through an explicit provider flag with a cached snapshot:

```bash
changegate scan \
  --plan tfplan.json \
  --cloud-context aws \
  --cache-dir .changegate/cache
```

When `--cloud-context aws` is used without a context file or cached snapshot, ChangeGate emits a warning and falls back to plan-only analysis without making network calls.

When a snapshot is provided, ChangeGate merges it into the review graph before rule evaluation. Plan evidence remains authoritative for planned changes, while cloud context adds live-only nodes, relationships, public exposure edges, and sensitive-asset context with explicit edge provenance. This lets findings and impact statements explain paths such as `public entrypoint -> workload -> datastore` using plan edges, live AWS edges, or both.

If cloud context confirms an existing plan edge, ChangeGate records the edge as `source=mixed`, keeps the exact merged source list in edge metadata, and uses the strongest confidence from the available evidence. This can raise an otherwise medium-confidence inferred path when live AWS context directly confirms the relationship. If context adds lower-confidence or partial evidence, attack paths remain warning-oriented rather than becoming high-confidence blocking decisions.

The merge can emit non-fatal diagnostics when live state changes the risk picture:

- `CLOUD_CONTEXT_PUBLIC_CONFLICT`: live AWS reports a resource as public, but the plan graph has no public inbound path.
- `CLOUD_CONTEXT_ATTACHMENT_CONFLICT`: live AWS reports an attachment or association that is absent from the plan graph.
- `CLOUD_CONTEXT_UNMANAGED_RELATIONSHIP`: a Terraform-managed resource is attached to an unmanaged live resource.

## Commands

```bash
changegate context aws identity
changegate context aws snapshot --out .changegate/aws-context.json
changegate context aws permissions-template
changegate context aws validate-permissions --context-file .changegate/aws-context.json
```

`identity` reads non-secret AWS metadata from environment variables such as `AWS_ACCOUNT_ID`, `AWS_REGION`, and `AWS_PROFILE`. It does not call AWS APIs.

`snapshot` writes a redacted context file shell by default and does not make network calls. With `--collect`, it uses AWS SDK for Go v2 and read-only AWS APIs to collect caller identity, enabled regions, network inventory, edge inventory, IAM metadata, compute metadata, and data-service metadata.

Network collection covers VPCs, subnets, route tables and route associations, internet gateways, NAT gateways, transit gateways, security groups, and network interfaces. Edge collection covers ALB/NLB listener and target-group routing, CloudFront distributions, API Gateway v2 APIs/routes/integrations, and Lambda Function URLs. IAM collection covers roles, trust policy shapes, permission boundaries, attached and inline policy action/resource shapes, instance profiles, and OIDC providers. Compute collection covers EC2 instances, Lambda functions, ECS services/task definitions, and EKS clusters/node groups. Data collection covers RDS instances/clusters/subnet groups, S3 public access block/encryption/logging/versioning/policy metadata, Secrets Manager secret metadata and resource policies, KMS key metadata and key policies, OpenSearch domains, ElastiCache clusters/replication groups, and EFS file systems/mount targets.

Partial AWS permission failures are written as snapshot diagnostics instead of crashing the command.

`permissions-template` prints a read-only IAM policy template for context collection.

The same policy is checked in at [`examples/aws-context-readonly-policy.json`](../examples/aws-context-readonly-policy.json) for teams that prefer to review or vendor the IAM document.

For a read-only sandbox walkthrough, see [AWS cloud context sandbox walkthrough](../examples/cloud-context-sandbox).

`validate-permissions` checks the snapshot capability flags and reports missing coverage as warnings. Capability flags are intentionally granular: broad domains such as `network`, `edge`, `compute`, and `data` are supported by service-level flags such as `route_tables`, `security_groups`, `network_interfaces`, `transit_gateways`, `elbv2`, `cloudfront`, `api_gateway`, `lambda_function_urls`, `ec2`, `ecs`, `lambda`, `eks`, `s3`, `s3_protection`, `rds`, `rds_subnet_groups`, `kms`, `kms_policies`, `secrets_manager`, `secrets_policies`, `opensearch`, `elasticache`, and `efs`. This lets partial-permission snapshots remain useful while making missing context explicit.

## Snapshot schema

Cloud context snapshots use schema version 2. The supported JSON Schema is published in [`schemas/cloud-context.schema.json`](../schemas/cloud-context.schema.json). Version 1 snapshots are not accepted; create a new snapshot with the current CLI or inventory job.

```json
{
  "version": 2,
  "provider": "aws",
  "generated_at": "2026-05-29T00:00:00Z",
  "account": {
    "id": "123456789012"
  },
  "capabilities": {
    "identity": true,
    "network": true,
    "route_tables": true,
    "security_groups": true,
    "network_interfaces": true,
    "transit_gateways": true,
    "edge": true,
    "elbv2": true,
    "cloudfront": true,
    "api_gateway": true,
    "lambda_function_urls": true,
    "iam": true,
    "iam_permission_boundaries": true,
    "compute": true,
    "ec2": true,
    "ecs": true,
    "lambda": true,
    "s3": true,
    "s3_protection": true,
    "rds": true,
    "rds_subnet_groups": true,
    "kms": true,
    "kms_policies": true,
    "secrets_manager": true,
    "secrets_policies": true,
    "eks": true,
    "opensearch": true,
    "elasticache": true,
    "efs": true
  },
  "edge": {
    "resources": {
      "aws_lb.edge": {
        "terraform_address": "aws_lb.edge",
        "arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/edge/abc123",
        "account_id": "123456789012",
        "type": "aws_lb",
        "region": "us-east-1",
        "tags": {
          "Name": "edge"
        },
        "public": true,
        "compensating_controls": ["expected_public_tls_edge"]
      }
    }
  },
  "data": {
    "resources": {
      "aws_db_instance.customer": {
        "terraform_address": "aws_db_instance.customer",
        "arn": "arn:aws:rds:us-east-1:123456789012:db:customer",
        "type": "aws_db_instance",
        "region": "us-east-1",
        "sensitivity": {
          "data": true,
          "reason": "customer data"
        },
        "deletion_protection": true
      }
    }
  },
  "network": {
    "resources": {
      "aws_security_group.admin": {
        "terraform_address": "aws_security_group.admin",
        "id": "sg-1234567890abcdef0",
        "type": "aws_security_group",
        "region": "us-east-1",
        "drift": {
          "ingress": "actual allows 0.0.0.0/0"
        }
      }
    }
  },
  "relationships": [
    {
      "from": "aws_lb.edge",
      "to": "aws_db_instance.customer",
      "type": "network_reaches",
      "source": "aws-elbv2+ec2",
      "confidence": "high"
    },
    {
      "from": "aws_security_group.admin",
      "to": "aws_db_instance.customer",
      "type": "protects",
      "source": "ec2",
      "confidence": "high"
    }
  ]
}
```

Top-level resource domains are:

- `network`: VPCs, subnets, route tables, security groups, route targets, and related reachability inventory.
- `iam`: principals, trust policies, permission policies, role attachments, and high-signal permission summaries.
- `data`: RDS, S3, Secrets Manager, KMS, OpenSearch, ElastiCache, and other sensitive data assets.
- `compute`: ECS, EKS, Lambda, EC2, task definitions, instance profiles, and workload identity.
- `edge`: ALB/NLB, CloudFront, API Gateway, public DNS, public IPs, and other entrypoints.

Resource entries are keyed by Terraform/OpenTofu address when available. Enrichment also indexes `terraform_address`, `arn`, `id`, selected known attributes such as `name` and `resource_id`, and selected tags such as `Name` and `terraform_address`. Sensitive tag values, sensitive-looking map values, drift values, and relationship source values are redacted on load/write.

Relationships use a uniform edge shape:

```json
{
  "from": "aws_lb.edge",
  "to": "aws_ecs_service.admin",
  "type": "routes_to",
  "source": "aws-elbv2",
  "confidence": "high"
}
```

## Enrichment behavior

Cloud context can downgrade expected public resources when compensating controls are present, such as:

- `expected_public_tls_edge`
- `edge_tls`
- `waf`
- `cloudfront_oac`
- `ip_allowlist`

Cloud context can upgrade findings when actual state shows stronger risk, such as:

- sensitive data relationships
- drift between plan assumptions and actual cloud state
- disabled encryption in actual state
- disabled S3 public access block in actual state

Context evidence is added to findings with `type: cloud_context`. API failures or missing permissions are diagnostics and do not create false confidence.
