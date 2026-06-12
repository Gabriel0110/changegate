# Attack Paths

## Principal aws_iam_role.github_actions can pass aws_iam_role.admin_execution and run lambda:UpdateFunctionCode

- Decision: `block`
- Severity: `critical`, confidence: `high`
- Confidence reason: high confidence: iam:PassRole plus compute mutation can execute code with the target role with explicit IAM policy evidence and no target-matching deny evidence
- Finding rules: `AWS_IAM_PASSROLE_FUNCTION_ESCALATION`
- Principal: `aws_iam_role.github_actions`
- Target: `aws_iam_role.admin_execution`

Affected resources:
- **Target:** `aws_iam_role.admin_execution` (`aws_iam_role`)
- **Principal:** `aws_iam_role.github_actions` (`aws_iam_role`)
- **Intermediate:** `aws_lambda_function.*` (`aws_lambda_function`)

Steps:
1. `aws_iam_role.github_actions` -> `aws_iam_role.admin_execution` via iam:PassRole: principal can pass a privileged or sensitive execution role
1. `aws_iam_role.github_actions` -> `aws_lambda_function.*` via lambda:UpdateFunctionCode: principal can mutate or launch compute that can use the passed role

Mitigations:
- Scope iam:PassRole to non-privileged execution roles and exact services.
- Separate compute mutation permissions from pass-role permissions.

References:
- https://github.com/Gabriel0110/changegate/blob/main/docs/attack-paths.md

## Principal aws_lambda_function.worker can assume privileged role aws_iam_role.admin_execution

- Decision: `block`
- Severity: `critical`, confidence: `high`
- Confidence reason: high confidence: explicit role assumption edge reaches a privileged or sensitive role with explicit graph evidence for every step
- Finding rules: `AWS_IAM_ASSUME_ADMIN_PATH`
- Principal: `aws_lambda_function.worker`
- Target: `aws_iam_role.admin_execution`

Affected resources:
- **Target:** `aws_iam_role.admin_execution` (`aws_iam_role`)
- **Principal:** `aws_lambda_function.worker` (`aws_lambda_function`)

Steps:
1. `aws_lambda_function.worker` -> `aws_iam_role.admin_execution` via sts:AssumeRole: Lambda function assumes execution role

Mitigations:
- Remove broad trust or require tightly scoped conditions and approval for privileged role assumption.

References:
- https://github.com/Gabriel0110/changegate/blob/main/docs/attack-paths.md
