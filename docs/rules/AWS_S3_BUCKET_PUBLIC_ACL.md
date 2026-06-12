# S3 bucket ACL grants public access

| Field | Value |
| --- | --- |
| Rule ID | `AWS_S3_BUCKET_PUBLIC_ACL` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects S3 bucket ACLs that grant public read or write permissions.

## Resources

- `aws_s3_bucket_acl`

## Why It Matters

Public exposure changes can create reachable entrypoints. ChangeGate reports this when the plan or graph evidence is strong enough to show the exposure path.

## Remediation

- Set the bucket ACL to `private`.
- Remove grants to AllUsers or AuthenticatedUsers.
- Prefer bucket policies scoped to exact service principals over ACL-based public access.

## References

- No external references.
