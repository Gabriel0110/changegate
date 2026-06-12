# CloudFront origin bucket is also public

| Field | Value |
| --- | --- |
| Rule ID | `AWS_CLOUDFRONT_S3_PUBLIC_MISMATCH` |
| Category | `public_exposure` |
| Severity | `high` |
| Confidence | `high` |
| Status | `stable` |
| Version | `0.1.0` |
| Policy pack | `aws-public-exposure` |

## What It Detects

Detects CloudFront distributions that route to an S3 bucket that is also publicly exposed.

## Resources

- `aws_cloudfront_distribution`
- `aws_s3_bucket`

## Why It Matters

Public exposure changes can create reachable entrypoints. ChangeGate reports this when the plan or graph evidence is strong enough to show the exposure path.

## Remediation

- Remove public CIDRs unless internet access is required.
- Prefer private subnets, internal load balancers, or authenticated edge controls.
- Document any intentional public exposure in policy or a time-bounded waiver.

## References

- No external references.
