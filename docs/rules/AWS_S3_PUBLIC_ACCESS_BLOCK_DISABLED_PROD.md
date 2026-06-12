# Production S3 public access block disabled

| Field | Value |
| --- | --- |
| Rule ID | `AWS_S3_PUBLIC_ACCESS_BLOCK_DISABLED_PROD` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects production S3 public access block resources that disable one or more protections.

## Resources

- `aws_s3_bucket_public_access_block`

## Why It Matters

Public exposure changes can create reachable entrypoints. ChangeGate reports this when the plan or graph evidence is strong enough to show the exposure path.

## Remediation

- Set `block_public_acls`, `block_public_policy`, `ignore_public_acls`, and `restrict_public_buckets` to `true`.
- Review any intentionally public production bucket through a policy exception or waiver.
- Confirm dependent CloudFront or application access uses private origin or scoped IAM access.

## References

- No external references.
