<!-- changegate-review -->

## ChangeGate Infrastructure Review: BLOCK

This change introduces 2 blocking infrastructure risks and requires remediation or an approved waiver.

### Security Impact

- Resources changed: 4
- Public entrypoints added: 2
- Sensitive assets touched: 2
- IAM permission changes: 1
- Network path changes: 2
- Data path changes: 2
- Review required: yes

### Risk Movement

- New critical risks: 0
- New high risks: 2
- New medium risks: 0
- Existing unchanged risks: 3
- Existing worsened risks: 1
- Existing improved risks: 0
- Resolved critical/high risks: 1

### Top Findings

1. `AWS_PUBLIC_ADMIN_SERVICE` `high/high` AWS PUBLIC ADMIN SERVICE on `aws_lb.admin`
   - Fix: Restrict public ingress or move the service behind an internal entrypoint.
   - Owner hints: `platform-security`
2. `AWS_STATEFUL_REPLACEMENT` `high/high` AWS STATEFUL REPLACEMENT on `aws_db_instance.customer`
   - Fix: Restrict public ingress or move the service behind an internal entrypoint.
   - Owner hints: `platform-security`

<details>
<summary>Finding details</summary>

#### `AWS_PUBLIC_ADMIN_SERVICE` AWS PUBLIC ADMIN SERVICE

- Resource: `aws_lb.admin`
- Severity/confidence: `high/high`
- Why this matters: A high-confidence infrastructure risk was introduced.
- Evidence: Public entrypoint reaches a sensitive downstream asset.
- Remediation: Make the load balancer internal or restrict ingress to approved CIDRs.

#### `AWS_STATEFUL_REPLACEMENT` AWS STATEFUL REPLACEMENT

- Resource: `aws_db_instance.customer`
- Severity/confidence: `high/high`
- Why this matters: A high-confidence infrastructure risk was introduced.
- Evidence: Public entrypoint reaches a sensitive downstream asset.
- Remediation: Make the load balancer internal or restrict ingress to approved CIDRs.

</details>

### Top Blast Radius

- `internet -> aws_lb.admin -> aws_ecs_service.admin -> aws_db_instance.customer`
  - Why this matters: A public entrypoint reaches a sensitive downstream asset.

### Attack Paths

- `AWS_PASSROLE_WITH_COMPUTE_MUTATION` `high/high` Deploy role can pass privileged role and mutate compute
  - Path: `DeveloperRole -> lambda:UpdateFunctionCode -> iam:PassRole -> AdminExecutionRole`

### Waivers and Baseline

- Active waivers: 1
- Expired waivers: 0
- Existing baseline findings: 3
- New findings: 2

### Ownership

- `platform-security` owns `aws_lb.admin`

### Required Action

- `security`: deployment decision requires review
- Restrict public ingress or move the service behind an internal entrypoint.

### Artifacts

- [Audit bundle](https://example.test/audit.zip)

<details>
<summary>Diagnostics</summary>

- `warning` `TEST_WARNING`: fixture diagnostic

</details>
