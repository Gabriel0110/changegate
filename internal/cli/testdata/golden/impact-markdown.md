# Security Impact Statement

Decision: BLOCK
Review required: Yes

This change introduces:
- 0 public entrypoints
- 1 sensitive asset touched
- 0 IAM permission changes
- 0 network path changes
- 1 data path change
- 0 active waivers

## Risk Clusters

- `high/high` Sensitive S3 bucket logging disabled
  - Decision: `block`
  - Affected resources: 1
  - Supporting findings: 1
  - Primary fix: Enable S3 server access logging or equivalent object access audit logging.
- `high/high` Sensitive S3 bucket versioning disabled
  - Decision: `block`
  - Affected resources: 1
  - Supporting findings: 1
  - Primary fix: Enable S3 versioning for sensitive buckets.
- `high/high` Stateful resource replacement
  - Decision: `block`
  - Affected resources: 1
  - Supporting findings: 1
  - Primary fix: Review stateful replacement, snapshot data, and require approval before apply.

## Risk Movement

| Metric | Count |
| --- | ---: |
| New critical risks | 0 |
| New high risks | 3 |
| New medium risks | 0 |
| Existing unchanged risks | 0 |
| Existing worsened risks | 0 |
| Existing improved risks | 0 |
| Resolved high risks | 0 |

## Top Findings

- `AWS_S3_SENSITIVE_BUCKET_LOGGING_DISABLED` `high/high` Sensitive S3 bucket logging disabled on `aws_s3_bucket.logs`
- `AWS_S3_SENSITIVE_BUCKET_VERSIONING_DISABLED` `high/high` Sensitive S3 bucket versioning disabled on `aws_s3_bucket.logs`
- `AWS_STATEFUL_REPLACEMENT` `high/high` Stateful resource replacement on `module.database.aws_db_instance.customer`

## Required Review

- `security`: deployment decision is block
- `data-owner`: sensitive asset is affected
