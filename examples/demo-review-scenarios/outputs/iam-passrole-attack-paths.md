# Attack Paths

## Principal aws_iam_role.github_actions can pass aws_iam_role.admin_execution and run lambda:UpdateFunctionCode

- ID: `attack-path-7df07ea9e4a947ee`
- Type: `iam_privilege_escalation`
- Kind: `identity`
- Decision: `block`
- Severity: `critical`
- Confidence: `high`
- Confidence reason: path confidence is based on plan graph evidence
- Source: `plan`
- Finding rules: `AWS_IAM_PASSROLE_FUNCTION_ESCALATION`
- Principal: `aws_iam_role.github_actions`
- Target: `aws_iam_role.admin_execution`

Affected resources:

- `aws_iam_role.admin_execution` `target` `aws_iam_role`
- `aws_iam_role.github_actions` `principal` `aws_iam_role`
- `aws_lambda_function.*` `intermediate` `aws_lambda_function`

Steps:

1. `aws_iam_role.github_actions` -> `aws_iam_role.admin_execution` via `iam:PassRole` (`plan/high`): principal can pass a privileged or sensitive execution role
1. `aws_iam_role.github_actions` -> `aws_lambda_function.*` via `lambda:UpdateFunctionCode` (`plan/high`): principal can mutate or launch compute that can use the passed role

Mitigations:

- Scope iam:PassRole to non-privileged execution roles and exact services.
- Separate compute mutation permissions from pass-role permissions.

References:

- docs/attack-paths.md

## Principal aws_iam_role.github_actions can assume privileged role aws_iam_role.admin_execution

- ID: `attack-path-a31c186104d8f960`
- Type: `iam_privilege_escalation`
- Kind: `identity`
- Decision: `block`
- Severity: `critical`
- Confidence: `high`
- Confidence reason: path confidence is based on plan graph evidence
- Source: `plan`
- Finding rules: `AWS_IAM_ASSUME_ADMIN_PATH`
- Principal: `aws_iam_role.github_actions`
- Target: `aws_iam_role.admin_execution`

Affected resources:

- `aws_iam_role.admin_execution` `target` `aws_iam_role`
- `aws_iam_role.github_actions` `principal` `aws_iam_role`

Steps:

1. `aws_iam_role.github_actions` -> `aws_iam_role.admin_execution` via `sts:AssumeRole` (`plan/high`): IAM policy allows assuming role

Mitigations:

- Remove broad trust or require tightly scoped conditions and approval for privileged role assumption.

References:

- docs/attack-paths.md

## Principal aws_iam_role.github_actions can update Lambda aws_lambda_function.worker with privileged execution role

- ID: `attack-path-e77edc25016019b3`
- Type: `iam_privilege_escalation`
- Kind: `identity`
- Decision: `block`
- Severity: `critical`
- Confidence: `high`
- Confidence reason: path confidence is based on plan graph evidence
- Source: `plan`
- Finding rules: `AWS_IAM_PASSROLE_FUNCTION_ESCALATION`
- Principal: `aws_iam_role.github_actions`
- Target: `aws_iam_role.admin_execution`

Affected resources:

- `aws_iam_role.admin_execution` `target` `aws_iam_role`
- `aws_iam_role.github_actions` `principal` `aws_iam_role`
- `aws_lambda_function.worker` `intermediate` `aws_lambda_function`

Steps:

1. `aws_iam_role.github_actions` -> `aws_lambda_function.worker` via `lambda:UpdateFunctionCode` (`plan/high`): principal can update executable Lambda code
1. `aws_lambda_function.worker` -> `aws_iam_role.admin_execution` via `uses execution role` (`plan/high`): function executes with privileged or sensitive role access

Mitigations:

- Remove function update access or move the function to a least-privilege execution role.

References:

- docs/attack-paths.md

## Principal aws_iam_role.github_actions can pass aws_iam_role.github_actions and run lambda:UpdateFunctionCode

- ID: `attack-path-b46c6e33c5d4925d`
- Type: `iam_privilege_escalation`
- Kind: `identity`
- Decision: `block`
- Severity: `critical`
- Confidence: `high`
- Confidence reason: path confidence is based on plan graph evidence
- Source: `plan`
- Finding rules: `AWS_IAM_PASSROLE_FUNCTION_ESCALATION`
- Principal: `aws_iam_role.github_actions`
- Target: `aws_iam_role.github_actions`

Affected resources:

- `aws_iam_role.github_actions` `target` `aws_iam_role`
- `aws_lambda_function.*` `intermediate` `aws_lambda_function`

Steps:

1. `aws_iam_role.github_actions` -> `aws_iam_role.github_actions` via `iam:PassRole` (`plan/high`): principal can pass a privileged or sensitive execution role
1. `aws_iam_role.github_actions` -> `aws_lambda_function.*` via `lambda:UpdateFunctionCode` (`plan/high`): principal can mutate or launch compute that can use the passed role

Mitigations:

- Scope iam:PassRole to non-privileged execution roles and exact services.
- Separate compute mutation permissions from pass-role permissions.

References:

- docs/attack-paths.md

## Principal aws_lambda_function.worker can assume privileged role aws_iam_role.admin_execution

- ID: `attack-path-67b4a1f132f5877e`
- Type: `iam_privilege_escalation`
- Kind: `identity`
- Decision: `block`
- Severity: `critical`
- Confidence: `high`
- Confidence reason: path confidence is based on plan graph evidence
- Source: `plan`
- Finding rules: `AWS_IAM_ASSUME_ADMIN_PATH`
- Principal: `aws_lambda_function.worker`
- Target: `aws_iam_role.admin_execution`

Affected resources:

- `aws_iam_role.admin_execution` `target` `aws_iam_role`
- `aws_lambda_function.worker` `principal` `aws_lambda_function`

Steps:

1. `aws_lambda_function.worker` -> `aws_iam_role.admin_execution` via `sts:AssumeRole` (`plan/high`): Lambda function assumes execution role

Mitigations:

- Remove broad trust or require tightly scoped conditions and approval for privileged role assumption.

References:

- docs/attack-paths.md
