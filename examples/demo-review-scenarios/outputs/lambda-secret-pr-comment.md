## ChangeGate: BLOCK

**2 risk clusters** from 4 findings: 4 blocking, 0 warnings, 0 suppressed.

### Decision Reasons

- **Lambda function URL is public:** Meets the configured block threshold.
- **Public entrypoint reaches sensitive data:** 3 supporting findings across 3 affected resources

### Risk Clusters

#### 1. Public entrypoint reaches sensitive data

- Severity: `critical`
- Confidence: `high`
- Decision: `block`
- Affected resources: 3
- Supporting findings: 3

**Fix:** Remove public exposure from the workload or scope secret access to a private workload path.

Rules:

- `AWS_PUBLIC_LAMBDA_URL_TO_SENSITIVE_DATA`
- `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`
- `AWS_PUBLIC_WORKLOAD_READS_SECRET`

#### 2. Lambda function URL is public

- Severity: `high`
- Confidence: `high`
- Decision: `block`
- Affected resources: 1
- Supporting findings: 1

**Fix:** Use AWS_IAM authorization or place the function behind an authenticated API layer.

Rules:

- `AWS_LAMBDA_PUBLIC_FUNCTION_URL`
