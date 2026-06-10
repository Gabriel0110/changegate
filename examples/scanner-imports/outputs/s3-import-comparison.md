# ChangeGate: BLOCK

| Metric | Value |
| --- | ---: |
| Risk clusters | 2 |
| Findings | 2 |
| Blocking | 1 |
| Warnings | 1 |
| Suppressed | 0 |
| Downgraded | 0 |
| Imported findings | 3 |
| Retained imported findings | 1 |
| Deduplicated imported findings | 2 |
| Native findings superseded imports | 2 |
| Correlated imported findings | 1 |
| Graph nodes | 1 |
| Graph edges | 0 |

## External scanner intelligence

ChangeGate imported 3 external findings, retained 1 after deduplication, and correlated 1 to the change graph.

| Source | Findings |
| --- | ---: |
| `checkov` | 1 |
| `kics` | 1 |
| `trivy` | 1 |

Key handling notes:
- `kics` `correlated` `aws_s3_bucket_policy.assets`: scanner finding matched a changed graph resource through graph.alias
- `checkov` `superseded_by_native` `aws_s3_bucket_policy.assets`: native ChangeGate finding covers the same resource and risk category with plan graph evidence (`AWS_S3_BUCKET_PUBLIC_POLICY`)
- `trivy` `superseded_by_native` `aws_s3_bucket_policy.assets`: native ChangeGate finding covers the same resource and risk category with plan graph evidence (`AWS_S3_BUCKET_PUBLIC_POLICY`)

## Decision reasons

- `MEETS_BLOCK_THRESHOLD` `S3 bucket policy grants public access`: finding meets block threshold

## Risk clusters

### S3 bucket policy grants public access

- Decision: `block`
- Severity: `high`, confidence: `high`
- Affected resources: 1
- Supporting findings: 1
- Rules: `AWS_S3_BUCKET_PUBLIC_POLICY`
- Primary fix: Remove public principals from the bucket policy and use CloudFront origin access control or scoped IAM principals.
- Resources: `aws_s3_bucket_policy.assets`

### S3 bucket policy allows public access

- Decision: `warn`
- Severity: `high`, confidence: `medium`
- Affected resources: 1
- Supporting findings: 1
- Rules: `EXT_KICS_381C3F2A_EF6F_4EFF_99F7_B169CDA3422C`
- Primary fix: Review the finding evidence and choose a resource-specific mitigation.
- Resources: `aws_s3_bucket_policy.assets`

## Finding details

### S3 bucket policy grants public access

- Rule: `AWS_S3_BUCKET_PUBLIC_POLICY`
- Resource: `aws_s3_bucket_policy.assets`
- Severity: `high`, confidence: `high`
- Fingerprint: `f961899ec107fe963350397289cf952b611b0164548340882659757cc8e8276d`

Detects S3 bucket policies that grant public read or write access.

Evidence:
- **Rule evidence:** S3 bucket policy grants public read or write access

Remediation:

**Primary fix:** Remove public principals from the bucket policy and use CloudFront origin access control or scoped IAM principals.

Recommended actions:
- Document any intentional public exposure in policy or a time-bounded waiver.
- Prefer private subnets, internal load balancers, or authenticated edge controls.
- Remove public CIDRs unless internet access is required.

Fix options:
- **Make the endpoint private** (preferred): Move the exposed resource behind private networking or an internal load balancer.
- **Restrict ingress**: Keep the endpoint public only for reviewed CIDRs or authenticated edge controls.

Review notes:
- Effort: medium
- Downtime risk: medium
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### S3 bucket policy allows public access

- Rule: `EXT_KICS_381C3F2A_EF6F_4EFF_99F7_B169CDA3422C`
- Resource: `aws_s3_bucket_policy.assets`
- Severity: `high`, confidence: `medium`
- Fingerprint: `d1a05322c9b77ff441fcfe03d280d3df7f8a2782c9224a36853fff43f134c542`

Evidence:
- **aws_s3_bucket_policy.assets:** finding imported from kics
- **aws_s3_bucket_policy.assets:** KICS query match
- **aws_s3_bucket_policy.assets:** imported finding correlated to changed graph resource

Remediation:

**Primary fix:** Review the finding evidence and choose a resource-specific mitigation.

Recommended actions:
- Add a targeted fix or a time-bounded waiver if the risk is accepted.
- Identify the owning team.
- Inspect the finding evidence.

Fix options:
- **Review evidence** (preferred): Use the finding evidence and owning team context to select a resource-specific mitigation.

Review notes:
- Effort: unknown
- Downtime risk: unknown
- Request owner review before apply.
- Validate whether missing context changes the risk.
