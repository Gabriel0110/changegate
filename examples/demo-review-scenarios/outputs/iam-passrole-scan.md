# ChangeGate: BLOCK

| Metric | Value |
| --- | ---: |
| Risk clusters | 1 |
| Findings | 3 |
| Blocking | 2 |
| Warnings | 1 |
| Suppressed | 0 |
| Downgraded | 0 |
| Graph nodes | 5 |
| Graph edges | 4 |

## Decision reasons

- **IAM principal can reach elevated access:** 3 supporting findings across 2 affected resources

## Risk clusters

### IAM principal can reach elevated access

- Decision: `block`
- Severity: `critical`, confidence: `high`
- Affected resources: 2
- Supporting findings: 3
- Rules: `AWS_IAM_ASSUME_ADMIN_PATH`, `AWS_IAM_PASSROLE_FUNCTION_ESCALATION`, `AWS_PASSROLE_WITH_COMPUTE_MUTATION`
- Primary fix: Remove broad trust or require tightly scoped conditions and approval for privileged role assumption.
- Resources: `aws_iam_role.admin_execution`, `aws_iam_role.github_actions`

## Finding details

### Principal aws_lambda_function.worker can assume privileged role aws_iam_role.admin_execution

- Rule: `AWS_IAM_ASSUME_ADMIN_PATH`
- Resource: `aws_iam_role.admin_execution`
- Severity: `critical`, confidence: `high`
- Fingerprint: `6762e3331d4284766f730e0b99b1cd4c381fc7776f5d80f28d2f6acfd33e36c1`

ChangeGate detected a high-signal infrastructure attack path.

Evidence:
- **Confidence:** high confidence: explicit role assumption edge reaches a privileged or sensitive role with explicit graph evidence for every step
- **Attack path:** principal can assume a privileged or sensitive role
- **Attack path step:** Lambda function assumes execution role
- 5 additional evidence items are available in JSON output.

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
- **Confidence:** high confidence: iam:PassRole plus compute mutation can execute code with the target role with explicit IAM policy evidence and no target-matching deny evidence
- **Attack path:** principal has lambda:UpdateFunctionCode through aws_iam_policy.deploy
- **Attack path step:** principal can pass a privileged or sensitive execution role
- **Attack path step:** principal can mutate or launch compute that can use the passed role
- 5 additional evidence items are available in JSON output.

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

### iam:PassRole grant in a compute-mutating plan

- Rule: `AWS_PASSROLE_WITH_COMPUTE_MUTATION`
- Resource: `aws_iam_role.github_actions`
- Severity: `high`, confidence: `medium`
- Fingerprint: `e70ddcbe94fb433d125ca3bb989beb18547eb41524a31653d718e6fd7bb1f34d`

Detects iam:PassRole grants in plans that also mutate compute resources. The attack-path engine emits the high-confidence block when the same principal can both pass the role and mutate compute.

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
- Request owner review before apply.
- Validate whether missing context changes the risk.
