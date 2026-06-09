# ChangeGate: BLOCK

| Metric                             | Value |
| ---------------------------------- | ----: |
| Risk clusters                      |     2 |
| Findings                           |     2 |
| Blocking                           |     1 |
| Warnings                           |     1 |
| Suppressed                         |     0 |
| Downgraded                         |     0 |
| Imported findings                  |     3 |
| Retained imported findings         |     1 |
| Deduplicated imported findings     |     2 |
| Native findings superseded imports |     2 |
| Correlated imported findings       |     1 |
| Graph nodes                        |     1 |
| Graph edges                        |     0 |

## External scanner intelligence

ChangeGate imported 3 external findings, retained 1 after deduplication, and correlated 1 to the change graph.

| Source    | Findings |
| --------- | -------: |
| `checkov` |        1 |
| `kics`    |        1 |
| `trivy`   |        1 |

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

- `rule` `policy`: S3 bucket policy grants public read or write access

Remediation:

- Remove public principals from the bucket policy and use CloudFront origin access control or scoped IAM principals.
- Document any intentional public exposure in policy or a time-bounded waiver.
- Prefer private subnets, internal load balancers, or authenticated edge controls.
- Remove public CIDRs unless internet access is required.
- Why this works: Reducing public reachability lowers exploitability and leaves fewer assets directly reachable from the internet.
- Fix confidence: `medium`
- Automatic patch: `false`
- Patch suggestion: Public exposure requires review (ChangeGate does not auto-apply exposure changes because safe CIDRs, proxy placement, and business intent are environment-specific.)
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### S3 bucket policy allows public access

- Rule: `EXT_KICS_381C3F2A_EF6F_4EFF_99F7_B169CDA3422C`
- Resource: `aws_s3_bucket_policy.assets`
- Severity: `high`, confidence: `medium`
- Fingerprint: `d1a05322c9b77ff441fcfe03d280d3df7f8a2782c9224a36853fff43f134c542`

Evidence:

- `external_scanner` `kics`: finding imported from kics
- `external_location` `main.tf:3`: KICS query match
- `external_correlation` `graph.alias`: imported finding correlated to changed graph resource

Remediation:

- Review the finding evidence and choose a resource-specific mitigation.
- Add a targeted fix or a time-bounded waiver if the risk is accepted.
- Identify the owning team.
- Inspect the finding evidence.
- Why this works: Unknown-risk findings require human review because the risk class is not specific enough for a safe patch.
- Fix confidence: `low`
- Automatic patch: `false`
- Patch suggestion: No automatic patch for unknown risk (The risk category is too broad to generate a safe Terraform/OpenTofu patch.)
- Next step: Request owner review before apply.
- Next step: Validate whether missing context changes the risk.
