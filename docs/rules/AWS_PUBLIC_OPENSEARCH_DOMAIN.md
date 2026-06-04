# Public OpenSearch domain

| Field       | Value                          |
| ----------- | ------------------------------ |
| Rule ID     | `AWS_PUBLIC_OPENSEARCH_DOMAIN` |
| Category    | `public_exposure`              |
| Severity    | `high`                         |
| Confidence  | `high`                         |
| Status      | `stable`                       |
| Version     | `0.1.0`                        |
| Policy pack | `aws-public-exposure`          |

## What It Detects

Detects OpenSearch domains with broad public access policies.

## Resources

- `aws_opensearch_domain`
- `aws_elasticsearch_domain`

## Why It Matters

Review the planned infrastructure change before apply.

## Remediation

- Review the planned change before apply.
- Constrain the risky permission, exposure, or destructive action to the minimum required scope.

## References

- No external references.
