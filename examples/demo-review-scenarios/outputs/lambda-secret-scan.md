# ChangeGate: BLOCK

| Metric | Value |
| --- | ---: |
| Risk clusters | 4 |
| Findings | 6 |
| Blocking | 6 |
| Warnings | 0 |
| Suppressed | 0 |
| Downgraded | 0 |
| Graph nodes | 4 |
| Graph edges | 5 |

## Decision reasons

- `MEETS_BLOCK_THRESHOLD` `Lambda function URL is public`: finding meets block threshold
- `MEETS_BLOCK_THRESHOLD` `Public Lambda URL reaches sensitive data`: finding meets block threshold
- `MEETS_BLOCK_THRESHOLD` `Public admin service reaches sensitive data`: Public admin service reaches sensitive data: 3 supporting findings across 3 affected resources
- `MEETS_BLOCK_THRESHOLD` `Public workload can read secret`: finding meets block threshold

## Risk clusters

### Public Lambda URL reaches sensitive data

- Decision: `block`
- Severity: `critical`, confidence: `high`
- Affected resources: 1
- Supporting findings: 1
- Rules: `AWS_PUBLIC_LAMBDA_URL_TO_SENSITIVE_DATA`
- Primary fix: Use AWS_IAM authorization or remove the downstream sensitive data capability.
- Resources: `aws_lambda_function_url.public_handler`

### Public admin service reaches sensitive data

- Decision: `block`
- Severity: `critical`, confidence: `high`
- Affected resources: 3
- Supporting findings: 3
- Rules: `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`, `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`
- Primary fix: Limit secret access to the smallest required workload role.
- Resources: `aws_lambda_function.public_handler`, `aws_lambda_function_url.public_handler`, `aws_secretsmanager_secret.customer`

### Public workload can read secret

- Decision: `block`
- Severity: `critical`, confidence: `high`
- Affected resources: 1
- Supporting findings: 1
- Rules: `AWS_PUBLIC_WORKLOAD_READS_SECRET`
- Primary fix: Remove public exposure from the workload or scope secret access to a private workload path.
- Resources: `aws_lambda_function.public_handler`

### Lambda function URL is public

- Decision: `block`
- Severity: `high`, confidence: `high`
- Affected resources: 1
- Supporting findings: 1
- Rules: `AWS_LAMBDA_PUBLIC_FUNCTION_URL`
- Primary fix: Use AWS_IAM authorization or place the function behind an authenticated API layer.
- Resources: `aws_lambda_function_url.public_handler`

## Finding details

### Public workload can read secret

- Rule: `AWS_PUBLIC_WORKLOAD_READS_SECRET`
- Resource: `aws_lambda_function.public_handler`
- Severity: `critical`, confidence: `high`
- Fingerprint: `51a0fe323974fe0d71dc77cb0defe592e650c642f2ae05eaf4cf735632322e59`

Detects internet-exposed workloads with graph-backed access to Secrets Manager secrets.

Evidence:
- **Graph path:** internet-exposed workload has a high-confidence graph path to a secret
- **Reachable sensitive asset:** sensitive graph target is reachable from public infrastructure
- **Graph edge:** Lambda environment references secret value
- 2 additional evidence items are available in JSON output.

Remediation:

**Primary fix:** Remove public exposure from the workload or scope secret access to a private workload path.

Recommended actions:
- Remove unauthenticated public entry points that invoke the workload.
- Scope `secretsmanager:GetSecretValue` to only the secret and role that require it.
- Split public request handling from private secret access when the endpoint must remain internet-facing.

Fix options:
- **Enable protection controls** (preferred): Turn on encryption, public-access blocks, and logging where supported.
- **Segment access**: Limit sensitive asset access to the workloads and roles that require it.

Review notes:
- Owner hint: `service=public-api`
- Effort: medium
- Downtime risk: low
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Public Lambda URL reaches sensitive data

- Rule: `AWS_PUBLIC_LAMBDA_URL_TO_SENSITIVE_DATA`
- Resource: `aws_lambda_function_url.public_handler`
- Severity: `critical`, confidence: `high`
- Fingerprint: `81a4761b98431a8af02278dd7b13a222c71ced8acd72550e7fcc38062b78829a`

Detects unauthenticated Lambda function URLs that invoke a function with graph-backed access to sensitive data.

Evidence:
- **Graph path:** public Lambda function URL invokes a workload with a high-confidence path to sensitive data
- **Reachable sensitive asset:** sensitive graph target is reachable from public infrastructure
- **Graph edge:** Lambda function URL invokes Lambda function
- **Graph edge:** Lambda environment references secret value
- 2 additional evidence items are available in JSON output.

Remediation:

**Primary fix:** Use AWS_IAM authorization or remove the downstream sensitive data capability.

Recommended actions:
- If the function must stay public, split sensitive operations into a private worker role or separate function.
- Remove secret, KMS, datastore, or bucket access that is not required by this public handler.
- Set the function URL `authorization_type` to `AWS_IAM` or place it behind an authenticated edge layer.

Fix options:
- **Enable protection controls** (preferred): Turn on encryption, public-access blocks, and logging where supported.
- **Segment access**: Limit sensitive asset access to the workloads and roles that require it.

Patch suggestion: Require IAM authorization for Lambda Function URL

```hcl
resource "aws_lambda_function_url" "public_handler" {
  authorization_type = "AWS_IAM"
}
```

Review the patch before applying it.

Review notes:
- Effort: medium
- Downtime risk: low
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Public Lambda Function URL aws_lambda_function_url.public_handler reaches secret aws_secretsmanager_secret.customer

- Rule: `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`
- Resource: `aws_secretsmanager_secret.customer`
- Severity: `critical`, confidence: `high`
- Fingerprint: `6ead9a881bbabce06ce7203b820aef5ddb9925ba0f4c01fbf306066e16dfa543`

ChangeGate detected a high-signal infrastructure attack path.

Evidence:
- **Attack path:** attack path type is public_to_sensitive_data
- **Attack path:** attack path kind is network
- **Confidence:** high confidence: every step from public entrypoint through workload to sensitive target is backed by explicit plan or cloud-context graph evidence
- **Graph path:** public entrypoint reaches sensitive asset
- **Attack path step:** Lambda function URL is internet exposed
- **Attack path step:** cloud context relationship
- 4 additional evidence items are available in JSON output.

Remediation:

**Primary fix:** Limit secret access to the smallest required workload role.

Recommended actions:
- Allow sensitive assets only from reviewed workload security groups and roles.
- Remove direct routing from public workloads to sensitive datastores or secrets.
- Remove the public route to the workload or restrict ingress to approved CIDRs.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.
- Segment the workload from sensitive data stores and secrets.

Fix options:
- **Enable protection controls** (preferred): Turn on encryption, public-access blocks, and logging where supported.
- **Segment access**: Limit sensitive asset access to the workloads and roles that require it.

Review notes:
- Effort: medium
- Downtime risk: low
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Lambda function URL is public

- Rule: `AWS_LAMBDA_PUBLIC_FUNCTION_URL`
- Resource: `aws_lambda_function_url.public_handler`
- Severity: `high`, confidence: `high`
- Fingerprint: `5325a0d1724c352cd39b4f0434d65a504bb8b19f3076196374925d3f0a9ca97c`

Detects Lambda function URLs that allow unauthenticated public access.

Evidence:
- **Rule evidence:** Lambda function URL allows unauthenticated public access
- 2 additional evidence items are available in JSON output.

Remediation:

**Primary fix:** Use AWS_IAM authorization or place the function behind an authenticated API layer.

Recommended actions:
- Document any intentionally public function URL with owner approval and monitoring coverage.
- If anonymous access is required, put the function behind API Gateway, CloudFront, WAF, or another reviewed edge control.
- Set the Lambda function URL `authorization_type` to `AWS_IAM` when callers can sign requests.

Fix options:
- **Make the endpoint private** (preferred): Move the exposed resource behind private networking or an internal load balancer.
- **Restrict ingress**: Keep the endpoint public only for reviewed CIDRs or authenticated edge controls.

Patch suggestion: Require IAM authorization for Lambda Function URL

```hcl
resource "aws_lambda_function_url" "public_handler" {
  authorization_type = "AWS_IAM"
}
```

Review the patch before applying it.

Review notes:
- Effort: medium
- Downtime risk: medium
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Public resource can reach sensitive datastore

- Rule: `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`
- Resource: `aws_lambda_function.public_handler`
- Severity: `high`, confidence: `high`
- Fingerprint: `c10ca0d1f103037ddc9eae903bcedaa61bf0e6f786360f2be0867e5193a1ac25`

Detects public resources that can reach sensitive data stores through the graph.

Evidence:
- **Graph path:** public resource has a high-confidence graph path to sensitive datastore
- **Reachable sensitive asset:** sensitive datastore is reachable from public resource
- **Graph edge:** Lambda environment references secret value
- 2 additional evidence items are available in JSON output.

Remediation:

**Primary fix:** Break the public-to-sensitive path with private networking, scoped security groups, or service isolation.

Recommended actions:
- Allow datastore access only from reviewed private workload security groups.
- Remove direct routing from public workloads to sensitive datastores.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.

Fix options:
- **Enable protection controls** (preferred): Turn on encryption, public-access blocks, and logging where supported.
- **Segment access**: Limit sensitive asset access to the workloads and roles that require it.

Review notes:
- Owner hint: `service=public-api`
- Effort: medium
- Downtime risk: low
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Public resource can reach sensitive datastore

- Rule: `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`
- Resource: `aws_lambda_function_url.public_handler`
- Severity: `high`, confidence: `high`
- Fingerprint: `62d80349cd8c9d99c7276268d5d8700fe1708a7247d6ae03f933943eb6db4708`

Detects public resources that can reach sensitive data stores through the graph.

Evidence:
- **Graph path:** public resource has a high-confidence graph path to sensitive datastore
- **Reachable sensitive asset:** sensitive datastore is reachable from public resource
- **Graph edge:** Lambda function URL invokes Lambda function
- **Graph edge:** Lambda environment references secret value
- 2 additional evidence items are available in JSON output.

Remediation:

**Primary fix:** Break the public-to-sensitive path with private networking, scoped security groups, or service isolation.

Recommended actions:
- Allow datastore access only from reviewed private workload security groups.
- Remove direct routing from public workloads to sensitive datastores.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.

Fix options:
- **Enable protection controls** (preferred): Turn on encryption, public-access blocks, and logging where supported.
- **Segment access**: Limit sensitive asset access to the workloads and roles that require it.

Review notes:
- Effort: medium
- Downtime risk: low
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.
