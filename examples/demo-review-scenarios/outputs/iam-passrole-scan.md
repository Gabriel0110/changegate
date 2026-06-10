# ChangeGate: BLOCK

| Metric | Value |
| --- | ---: |
| Risk clusters | 1 |
| Findings | 5 |
| Blocking | 5 |
| Warnings | 0 |
| Suppressed | 0 |
| Downgraded | 0 |
| Graph nodes | 5 |
| Graph edges | 5 |

## Decision reasons

- `MEETS_BLOCK_THRESHOLD` `IAM principal can reach elevated access`: IAM principal can reach elevated access: 5 supporting findings across 2 affected resources

## Risk clusters

### IAM principal can reach elevated access

- Decision: `block`
- Severity: `critical`, confidence: `high`
- Affected resources: 2
- Supporting findings: 5
- Rules: `AWS_IAM_ASSUME_ADMIN_PATH`, `AWS_IAM_PASSROLE_FUNCTION_ESCALATION`, `AWS_PASSROLE_WITH_COMPUTE_MUTATION`, `AWS_ROLE_ASSUME_ADMIN_PATH`
- Primary fix: Remove broad trust or require tightly scoped conditions and approval for privileged role assumption.
- Resources: `aws_iam_role.admin_execution`, `aws_iam_role.github_actions`

## Finding details

### Principal aws_iam_role.github_actions can assume privileged role aws_iam_role.admin_execution

- Rule: `AWS_IAM_ASSUME_ADMIN_PATH`
- Resource: `aws_iam_role.admin_execution`
- Severity: `critical`, confidence: `high`
- Fingerprint: `6762e3331d4284766f730e0b99b1cd4c381fc7776f5d80f28d2f6acfd33e36c1`

ChangeGate detected a high-signal infrastructure attack path.

Evidence:
- **Attack path:** attack path type is iam_privilege_escalation
- **Attack path:** attack path kind is identity
- **Confidence:** high confidence: explicit role assumption edge reaches a privileged or sensitive role with explicit graph evidence for every step
- **Attack path:** principal can assume a privileged or sensitive role
- **Attack path step:** IAM policy allows assuming role
- 3 additional evidence items are available in JSON output.

Remediation:

**Primary fix:** Remove broad trust or require tightly scoped conditions and approval for privileged role assumption.

Recommended actions:
- Add explicit boundaries where role assumption is required.
- Avoid administrator policy attachment on roles that are assumable from deploy or external identities.
- Restrict trust policies to exact principals and expected conditions.

Fix options:
- **Scope privileged actions** (preferred): Replace wildcard IAM actions and resources with exact deployment permissions.
- **Split duties**: Separate role-passing, trust-management, and compute-mutation permissions across different principals.

Review notes:
- Effort: medium
- Downtime risk: low
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Principal aws_iam_role.github_actions can pass aws_iam_role.admin_execution and run lambda:UpdateFunctionCode

- Rule: `AWS_IAM_PASSROLE_FUNCTION_ESCALATION`
- Resource: `aws_iam_role.admin_execution`
- Severity: `critical`, confidence: `high`
- Fingerprint: `501d8c482391fa4e7f9e84dd8760da2a140e4b0741a8b8465feee2fecffa1071`

ChangeGate detected a high-signal infrastructure attack path.

Evidence:
- **Attack path:** attack path type is iam_privilege_escalation
- **Attack path:** attack path kind is identity
- **Confidence:** high confidence: iam:PassRole plus compute mutation can execute code with the target role with explicit IAM policy evidence and no contradicting deny statement
- **Attack path:** principal has lambda:UpdateFunctionCode through aws_iam_policy.deploy
- **Attack path step:** principal can pass a privileged or sensitive execution role
- **Attack path step:** principal can mutate or launch compute that can use the passed role
- 3 additional evidence items are available in JSON output.

Remediation:

**Primary fix:** Scope iam:PassRole to non-privileged execution roles and exact services.

Recommended actions:
- Remove wildcard `iam:PassRole` grants.
- Restrict function or service mutation actions to explicitly owned resources.
- Separate compute mutation permissions from pass-role permissions.
- Use conditions such as `iam:PassedToService` where appropriate.

Fix options:
- **Scope privileged actions** (preferred): Replace wildcard IAM actions and resources with exact deployment permissions.
- **Split duties**: Separate role-passing, trust-management, and compute-mutation permissions across different principals.

Review notes:
- Effort: medium
- Downtime risk: low
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Principal aws_iam_role.github_actions can pass aws_iam_role.github_actions and run lambda:UpdateFunctionCode

- Rule: `AWS_IAM_PASSROLE_FUNCTION_ESCALATION`
- Resource: `aws_iam_role.github_actions`
- Severity: `critical`, confidence: `high`
- Fingerprint: `23de487894723fa6c57514edfff547d052035ab68cdefc6c1d0ea5547c6cc64e`

ChangeGate detected a high-signal infrastructure attack path.

Evidence:
- **Attack path:** attack path type is iam_privilege_escalation
- **Attack path:** attack path kind is identity
- **Confidence:** high confidence: iam:PassRole plus compute mutation can execute code with the target role with explicit IAM policy evidence and no contradicting deny statement
- **Attack path:** principal has lambda:UpdateFunctionCode through aws_iam_policy.deploy
- **Attack path step:** principal can pass a privileged or sensitive execution role
- **Attack path step:** principal can mutate or launch compute that can use the passed role
- 3 additional evidence items are available in JSON output.

Remediation:

**Primary fix:** Scope iam:PassRole to non-privileged execution roles and exact services.

Recommended actions:
- Remove wildcard `iam:PassRole` grants.
- Restrict function or service mutation actions to explicitly owned resources.
- Separate compute mutation permissions from pass-role permissions.
- Use conditions such as `iam:PassedToService` where appropriate.

Fix options:
- **Scope privileged actions** (preferred): Replace wildcard IAM actions and resources with exact deployment permissions.
- **Split duties**: Separate role-passing, trust-management, and compute-mutation permissions across different principals.

Review notes:
- Effort: medium
- Downtime risk: low
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### iam:PassRole with compute mutation

- Rule: `AWS_PASSROLE_WITH_COMPUTE_MUTATION`
- Resource: `aws_iam_role.github_actions`
- Severity: `high`, confidence: `high`
- Fingerprint: `e70ddcbe94fb433d125ca3bb989beb18547eb41524a31653d718e6fd7bb1f34d`

Detects IAM principals that can pass roles and mutate compute resources.

Evidence:
- **aws_iam_policy.deploy:** IAM policy allows passing role
- **Rule evidence:** same plan mutates compute resources

Remediation:

**Primary fix:** Separate iam:PassRole grants from compute mutation or scope passable roles tightly.

Recommended actions:
- Constrain trust policies to expected principals and conditions.
- Replace wildcard actions and resources with least-privilege statements.
- Separate deploy-time permissions from runtime permissions.

Fix options:
- **Scope privileged actions** (preferred): Replace wildcard IAM actions and resources with exact deployment permissions.
- **Split duties**: Separate role-passing, trust-management, and compute-mutation permissions across different principals.

Review notes:
- Effort: medium
- Downtime risk: low
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.

### Role assumption path to admin role

- Rule: `AWS_ROLE_ASSUME_ADMIN_PATH`
- Resource: `aws_iam_role.github_actions`
- Severity: `high`, confidence: `high`
- Fingerprint: `cfa826d3c02acfcae34f9877df1dc9328404dad67e57045602272812db11a236`

Detects graph paths that allow a principal to assume an administrator role.

Evidence:
- **Rule evidence:** principal can assume admin role

Remediation:

**Primary fix:** Remove the assume-role path or require a tightly scoped break-glass workflow.

Recommended actions:
- Constrain trust policies to expected principals and conditions.
- Replace wildcard actions and resources with least-privilege statements.
- Separate deploy-time permissions from runtime permissions.

Fix options:
- **Scope privileged actions** (preferred): Replace wildcard IAM actions and resources with exact deployment permissions.
- **Split duties**: Separate role-passing, trust-management, and compute-mutation permissions across different principals.

Review notes:
- Effort: medium
- Downtime risk: low
- Attach evidence of the selected mitigation before apply.
- Treat as release-blocking unless a reviewer approves a time-bounded waiver.
