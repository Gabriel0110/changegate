## ChangeGate: BLOCK

**2 risk clusters** from 4 findings: 4 blocking, 0 warnings, 0 suppressed.

### Decision Reasons

- `MEETS_BLOCK_THRESHOLD` `Lambda function URL is public`: finding meets block threshold
- `MEETS_BLOCK_THRESHOLD` `Public admin service reaches sensitive data`: Public admin service reaches sensitive data: 3 supporting findings across 3 affected resources

### Risk Clusters

#### 1. Public admin service reaches sensitive data

- Severity: `critical`
- Confidence: `high`
- Decision: `block`
- Affected resources: 3
- Supporting findings: 3

**Fix:** Limit secret access to the smallest required workload role.

Rules:

- `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`
- `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`

#### 2. Lambda function URL is public

- Severity: `high`
- Confidence: `high`
- Decision: `block`
- Affected resources: 1
- Supporting findings: 1

**Fix:** Use AWS_IAM authorization or place the function behind an authenticated API layer.

Rules:

- `AWS_LAMBDA_PUBLIC_FUNCTION_URL`
