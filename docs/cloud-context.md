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

```json
{
  "version": 1,
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
  "resources": {
    "aws_lb.edge": {
      "address": "aws_lb.edge",
      "region": "us-east-1",
      "compensating_controls": ["expected_public_tls_edge"]
    },
    "aws_lb.public": {
      "address": "aws_lb.public",
      "related_sensitive_data": ["aws_db_instance.customer"],
      "drift": {
        "publicly_accessible": "actual true, plan false"
      }
    }
  }
}
```

Resource entries are keyed by Terraform/OpenTofu address. Sensitive tag values and sensitive-looking string fields are redacted on load.

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
