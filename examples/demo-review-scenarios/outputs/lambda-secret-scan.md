# ChangeGate: BLOCK

| Metric        | Value |
| ------------- | ----: |
| Risk clusters |     2 |
| Findings      |     4 |
| Blocking      |     4 |
| Warnings      |     0 |
| Suppressed    |     0 |
| Downgraded    |     0 |
| Graph nodes   |     4 |
| Graph edges   |     5 |

## Decision reasons

- `MEETS_BLOCK_THRESHOLD` `Lambda function URL is public`: finding meets block threshold
- `MEETS_BLOCK_THRESHOLD` `Public admin service reaches sensitive data`: Public admin service reaches sensitive data: 3 supporting findings across 3 affected resources

## Risk clusters

### Public admin service reaches sensitive data

- Decision: `block`
- Severity: `critical`, confidence: `high`
- Affected resources: 3
- Supporting findings: 3
- Rules: `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`, `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`
- Primary fix: Limit secret access to the smallest required workload role.
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

### Public entrypoint aws_lambda_function_url.public_handler reaches sensitive asset aws_secretsmanager_secret.customer

- Rule: `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`
- Resource: `aws_secretsmanager_secret.customer`
- Severity: `critical`, confidence: `high`
- Fingerprint: `6ead9a881bbabce06ce7203b820aef5ddb9925ba0f4c01fbf306066e16dfa543`

ChangeGate detected a high-signal infrastructure attack path.

Evidence:

- `attack_path` `attack_path.id`: attack path attack-path-810cccdbe74f8f34 produced block decision
- `attack_path` `attack_path.type`: attack path type is public_to_sensitive_data
- `attack_path` `attack_path.kind`: attack path kind is network
- `attack_path` `attack_path.confidence_reason`: path confidence is based on mixed graph evidence
- `attack_path.graph_path` `graph.path`: public entrypoint reaches sensitive asset
- `attack_path` `attack_path.source`: attack path source is mixed
- `attack_path` `attack_path.affected_resources`: attack path affected resources are linked to this finding
- `attack_path.step` `has_public_access`: Lambda function URL is internet exposed
- `attack_path.step` `routes_to`: cloud context relationship
- `attack_path.step` `reads_secret`: Lambda environment references secret value

Remediation:

- Limit secret access to the smallest required workload role.
- Allow sensitive assets only from reviewed workload security groups and roles.
- Limit secret access to the smallest required workload role.
- Remove direct routing from public workloads to sensitive datastores or secrets.
- Remove the public route to the workload or restrict ingress to approved CIDRs.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.
- Segment the workload from sensitive data stores and secrets.
- Why this works: Removing any required step breaks the attack path before deployment.
- Fix confidence: `medium`
- Automatic patch: `false`
- Patch suggestion: Attack path requires topology review (ChangeGate does not auto-patch multi-resource attack paths because the correct fix depends on service ownership, routing intent, and approved access patterns.)
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Lambda function URL is public

- Rule: `AWS_LAMBDA_PUBLIC_FUNCTION_URL`
- Resource: `aws_lambda_function_url.public_handler`
- Severity: `high`, confidence: `high`
- Fingerprint: `5325a0d1724c352cd39b4f0434d65a504bb8b19f3076196374925d3f0a9ca97c`

Detects Lambda function URLs that allow unauthenticated public access.

Evidence:

- `rule` `authorization_type`: Lambda function URL allows unauthenticated public access
- `cloud_context` `cloud_context.account`: AWS account context attached
- `cloud_context` `cloud_context.region`: AWS region context attached

Remediation:

- Use AWS_IAM authorization or place the function behind an authenticated API layer.
- Document any intentional public exposure in policy or a time-bounded waiver.
- Prefer private subnets, internal load balancers, or authenticated edge controls.
- Remove public CIDRs unless internet access is required.
- Why this works: Reducing public reachability lowers exploitability and leaves fewer assets directly reachable from the internet.
- Fix confidence: `medium`
- Automatic patch: `false`
- Patch suggestion: Public exposure requires review (ChangeGate does not auto-apply exposure changes because safe CIDRs, proxy placement, and business intent are environment-specific.)
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Public resource can reach sensitive datastore

- Rule: `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`
- Resource: `aws_lambda_function.public_handler`
- Severity: `high`, confidence: `high`
- Fingerprint: `c10ca0d1f103037ddc9eae903bcedaa61bf0e6f786360f2be0867e5193a1ac25`

Detects public resources that can reach sensitive data stores through the graph.

Evidence:

- `rule` `graph.path`: public resource has a high-confidence graph path to sensitive datastore
- `rule` `graph.target`: sensitive datastore is reachable from public resource
- `rule` `graph.edge`: Lambda environment references secret value
- `cloud_context` `cloud_context.account`: AWS account context attached
- `cloud_context` `cloud_context.region`: AWS region context attached

Remediation:

- Break the public-to-sensitive path with private networking, scoped security groups, or service isolation.
- Allow datastore access only from reviewed private workload security groups.
- Remove direct routing from public workloads to sensitive datastores.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.
- Why this works: The datastore is reachable only while each graph edge remains in place; removing public exposure, routing, or datastore access breaks the path.
- Fix confidence: `medium`
- Automatic patch: `false`
- Patch suggestion: Datastore reachability requires topology review (ChangeGate does not auto-patch public-to-datastore paths because the correct fix depends on service ownership, routing intent, security groups, and approved access patterns.)
- Owner hints: `service=public-api`
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Public resource can reach sensitive datastore

- Rule: `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`
- Resource: `aws_lambda_function_url.public_handler`
- Severity: `high`, confidence: `high`
- Fingerprint: `62d80349cd8c9d99c7276268d5d8700fe1708a7247d6ae03f933943eb6db4708`

Detects public resources that can reach sensitive data stores through the graph.

Evidence:

- `rule` `graph.path`: public resource has a high-confidence graph path to sensitive datastore
- `rule` `graph.target`: sensitive datastore is reachable from public resource
- `rule` `graph.edge`: Lambda function URL invokes Lambda function
- `rule` `graph.edge`: Lambda environment references secret value
- `cloud_context` `cloud_context.account`: AWS account context attached
- `cloud_context` `cloud_context.region`: AWS region context attached

Remediation:

- Break the public-to-sensitive path with private networking, scoped security groups, or service isolation.
- Allow datastore access only from reviewed private workload security groups.
- Remove direct routing from public workloads to sensitive datastores.
- Restrict the public entrypoint to approved CIDRs or authenticated edge controls.
- Why this works: The datastore is reachable only while each graph edge remains in place; removing public exposure, routing, or datastore access breaks the path.
- Fix confidence: `medium`
- Automatic patch: `false`
- Patch suggestion: Datastore reachability requires topology review (ChangeGate does not auto-patch public-to-datastore paths because the correct fix depends on service ownership, routing intent, security groups, and approved access patterns.)
- Next step: Attach evidence of the selected mitigation before apply.
- Next step: Treat as release-blocking unless a reviewer approves a time-bounded waiver.
