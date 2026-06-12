# ChangeGate: BLOCK

| Metric | Value |
| --- | ---: |
| Risk clusters | 2 |
| Findings | 4 |
| Blocking | 4 |
| Warnings | 0 |
| Suppressed | 0 |
| Downgraded | 0 |
| Graph nodes | 4 |
| Graph edges | 5 |

## Decision reasons

- **Lambda function URL is public:** Meets the configured block threshold.
- **Public entrypoint reaches sensitive data:** 3 supporting findings across 3 affected resources

## Risk clusters

### Public entrypoint reaches sensitive data

- Decision: `block`
- Severity: `critical`, confidence: `high`
- Affected resources: 3
- Supporting findings: 3
- Rules: `AWS_PUBLIC_LAMBDA_URL_TO_SENSITIVE_DATA`, `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`, `AWS_PUBLIC_WORKLOAD_READS_SECRET`
- Primary fix: Remove public exposure from the workload or scope secret access to a private workload path.
- Resources: `aws_lambda_function.public_handler`, `aws_lambda_function_url.public_handler`, `aws_secretsmanager_secret.customer`

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
- **Break public invocation** (preferred): Remove anonymous/public routes to the workload or require authenticated ingress.
- **Move secret access private**: Use a private worker or narrower role for the code path that reads the secret.

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
- **Authenticate the public entrypoint** (preferred): Require IAM-signed requests or put the Lambda behind an authenticated API/edge layer.
- **Split public and private work**: Keep public request handling separate from the role or function that can read sensitive data.

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
- Fingerprint: `d8877f4f35f787cc76bcd3482800da147af19059fd86544684db373e5bd0bd3c`

ChangeGate detected a high-signal infrastructure attack path.

Evidence:
- **Confidence:** high confidence: every step from public entrypoint through workload to sensitive target is backed by explicit plan or cloud-context graph evidence
- **Graph path:** public entrypoint reaches sensitive asset
- **Attack path step:** Lambda function URL is internet exposed
- **Attack path step:** Lambda function URL invokes Lambda function
- **Attack path step:** Lambda environment references secret value
- 5 additional evidence items are available in JSON output.

Remediation:

**Primary fix:** Limit secret access to the smallest required workload role.

Recommended actions:
- Allow sensitive assets only from reviewed workload security groups and roles.
- Remove direct routing from public workloads to sensitive datastores or secrets.
- Remove the public route to the workload or restrict ingress to approved CIDRs.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.
- Segment the workload from sensitive data stores and secrets.

Fix options:
- **Break the reachable path** (preferred): Remove one required edge between the public entrypoint, workload, and sensitive asset.
- **Constrain sensitive access**: Allow the sensitive asset only from reviewed private workload identities or security groups.

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
- **Require IAM authorization** (preferred): Set the function URL authorization type to AWS_IAM for signed callers.
- **Move behind a reviewed edge layer**: Use API Gateway, CloudFront, WAF, or an application gateway when anonymous internet access is intentional.

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
