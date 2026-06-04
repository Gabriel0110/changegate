# S3 bucket ACL grants public access

| Field       | Value                      |
| ----------- | -------------------------- |
| Rule ID     | `AWS_S3_BUCKET_PUBLIC_ACL` |
| Category    | `public_exposure`          |
| Severity    | `high`                     |
| Confidence  | `high`                     |
| Status      | `stable`                   |
| Version     | `0.1.0`                    |
| Policy pack | `aws-public-exposure`      |

## What It Detects

Detects S3 bucket ACLs that grant public read or write permissions.

## Resources

- `aws_s3_bucket_acl`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
