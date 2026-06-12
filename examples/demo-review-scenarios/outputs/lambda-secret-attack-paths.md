# Attack Paths

## Public Lambda Function URL aws_lambda_function_url.public_handler reaches secret aws_secretsmanager_secret.customer

- Decision: `block`
- Severity: `critical`, confidence: `high`
- Confidence reason: high confidence: every step from public entrypoint through workload to sensitive target is backed by explicit plan or cloud-context graph evidence
- Finding rules: `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`
- Entrypoint: `aws_lambda_function_url.public_handler`
- Target: `aws_secretsmanager_secret.customer`

Affected resources:
- **Intermediate:** `aws_lambda_function.public_handler` (`aws_lambda_function`)
- **Entrypoint:** `aws_lambda_function_url.public_handler` (`aws_lambda_function_url`)
- **Sensitive Asset:** `aws_secretsmanager_secret.customer` (`aws_secretsmanager_secret`)
- **Intermediate:** `internet`

Steps:
1. `internet` -> `aws_lambda_function_url.public_handler` via Has Public Access: Lambda function URL is internet exposed
1. `aws_lambda_function_url.public_handler` -> `aws_lambda_function.public_handler` via Invokes: Lambda function URL invokes Lambda function
1. `aws_lambda_function.public_handler` -> `aws_secretsmanager_secret.customer` via Reads Secret: Lambda environment references secret value

Mitigations:
- Limit secret access to the smallest required workload role.
- Remove the public route to the workload or restrict ingress to approved CIDRs.
- Segment the workload from sensitive data stores and secrets.

References:
- https://github.com/Gabriel0110/changegate/blob/main/docs/attack-paths.md
