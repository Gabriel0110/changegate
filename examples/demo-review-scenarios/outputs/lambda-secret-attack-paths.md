# Attack Paths

## Public Lambda Function URL aws_lambda_function_url.public_handler reaches secret aws_secretsmanager_secret.customer

- ID: `attack-path-0eeccbff14f69abe`
- Type: `public_to_sensitive_data`
- Kind: `network`
- Decision: `block`
- Severity: `critical`
- Confidence: `high`
- Confidence reason: high confidence: every step from public entrypoint through workload to sensitive target is backed by explicit plan or cloud-context graph evidence
- Source: `mixed`
- Finding rules: `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`
- Entrypoint: `aws_lambda_function_url.public_handler`
- Target: `aws_secretsmanager_secret.customer`

Affected resources:
- `aws_lambda_function.public_handler` `intermediate` `aws_lambda_function`
- `aws_lambda_function_url.public_handler` `entrypoint` `aws_lambda_function_url`
- `aws_secretsmanager_secret.customer` `sensitive_asset` `aws_secretsmanager_secret`
- `internet` `intermediate`

Steps:
1. `internet` -> `aws_lambda_function_url.public_handler` via `has_public_access` (`mixed/high`): Lambda function URL is internet exposed
1. `aws_lambda_function_url.public_handler` -> `aws_lambda_function.public_handler` via `invokes` (`plan/high`): Lambda function URL invokes Lambda function
1. `aws_lambda_function.public_handler` -> `aws_secretsmanager_secret.customer` via `reads_secret` (`mixed/high`): Lambda environment references secret value

Mitigations:
- Limit secret access to the smallest required workload role.
- Remove the public route to the workload or restrict ingress to approved CIDRs.
- Segment the workload from sensitive data stores and secrets.

References:
- docs/attack-paths.md

## Public Lambda Function URL aws_lambda_function_url.public_handler reaches secret aws_secretsmanager_secret.customer

- ID: `attack-path-810cccdbe74f8f34`
- Type: `public_to_sensitive_data`
- Kind: `network`
- Decision: `block`
- Severity: `critical`
- Confidence: `high`
- Confidence reason: high confidence: every step from public entrypoint through workload to sensitive target is backed by explicit plan or cloud-context graph evidence
- Source: `mixed`
- Finding rules: `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`
- Entrypoint: `aws_lambda_function_url.public_handler`
- Target: `aws_secretsmanager_secret.customer`

Affected resources:
- `aws_lambda_function.public_handler` `intermediate` `aws_lambda_function`
- `aws_lambda_function_url.public_handler` `entrypoint` `aws_lambda_function_url`
- `aws_secretsmanager_secret.customer` `sensitive_asset` `aws_secretsmanager_secret`
- `internet` `intermediate`

Steps:
1. `internet` -> `aws_lambda_function_url.public_handler` via `has_public_access` (`mixed/high`): Lambda function URL is internet exposed
1. `aws_lambda_function_url.public_handler` -> `aws_lambda_function.public_handler` via `routes_to` (`cloud_context/high`): cloud context relationship
1. `aws_lambda_function.public_handler` -> `aws_secretsmanager_secret.customer` via `reads_secret` (`mixed/high`): Lambda environment references secret value

Mitigations:
- Limit secret access to the smallest required workload role.
- Remove the public route to the workload or restrict ingress to approved CIDRs.
- Segment the workload from sensitive data stores and secrets.

References:
- docs/attack-paths.md
