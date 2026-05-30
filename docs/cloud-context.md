# Cloud Context

ChangeGate is credential-free and offline by default. Cloud context is explicitly opt-in and can be provided through an offline snapshot:

```bash
changegate context aws snapshot --out .changegate/aws-context.json
changegate scan --plan tfplan.json --context-file .changegate/aws-context.json
```

Or through an explicit provider flag with a cached snapshot:

```bash
changegate scan \
  --plan tfplan.json \
  --cloud-context aws \
  --cache-dir .changegate/cache
```

When `--cloud-context aws` is used without a context file or cached snapshot, ChangeGate emits a warning and falls back to plan-only analysis without making network calls.

## Commands

```bash
changegate context aws identity
changegate context aws snapshot --out .changegate/aws-context.json
changegate context aws permissions-template
changegate context aws validate-permissions --context-file .changegate/aws-context.json
```

`identity` reads non-secret AWS metadata from environment variables such as `AWS_ACCOUNT_ID`, `AWS_REGION`, and `AWS_PROFILE`. It does not call AWS APIs.

`snapshot` writes a redacted context file shell. The current implementation does not perform live AWS inventory collection; teams can enrich the snapshot from their own read-only inventory jobs.

`permissions-template` prints a read-only IAM policy template for context collection.

`validate-permissions` checks the snapshot capability flags and reports missing coverage as warnings.

## Snapshot schema

Cloud context snapshots use schema version 2. The supported JSON Schema is published in [`schemas/cloud-context.schema.json`](../schemas/cloud-context.schema.json). Version 1 snapshots are not accepted; regenerate old snapshots with the current CLI or inventory job.

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
    "security_groups": true,
    "iam": true,
    "s3": true,
    "rds": true,
    "kms": true,
    "secrets_manager": true,
    "eks": true
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

* `network`: VPCs, subnets, route tables, security groups, route targets, and related reachability inventory.
* `iam`: principals, trust policies, permission policies, role attachments, and high-signal permission summaries.
* `data`: RDS, S3, Secrets Manager, KMS, OpenSearch, ElastiCache, and other sensitive data assets.
* `compute`: ECS, EKS, Lambda, EC2, task definitions, instance profiles, and workload identity.
* `edge`: ALB/NLB, CloudFront, API Gateway, public DNS, public IPs, and other entrypoints.

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

* `expected_public_tls_edge`
* `edge_tls`
* `waf`
* `cloudfront_oac`
* `ip_allowlist`

Cloud context can upgrade findings when actual state shows stronger risk, such as:

* sensitive data relationships
* drift between plan assumptions and actual cloud state
* disabled encryption in actual state
* disabled S3 public access block in actual state

Context evidence is added to findings with `type: cloud_context`. API failures or missing permissions are diagnostics and do not create false confidence.
