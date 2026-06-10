## ChangeGate: BLOCK

**4 risk clusters** from 6 findings: 6 blocking, 0 warnings, 0 suppressed.

### Decision Reasons

- `MEETS_BLOCK_THRESHOLD` `Lambda function URL is public`: finding meets block threshold
- `MEETS_BLOCK_THRESHOLD` `Public Lambda URL reaches sensitive data`: finding meets block threshold
- `MEETS_BLOCK_THRESHOLD` `Public admin service reaches sensitive data`: Public admin service reaches sensitive data: 3 supporting findings across 3 affected resources
- ... 1 more reasons

### Risk Clusters

#### 1. Public Lambda URL reaches sensitive data

- Severity: `critical`
- Confidence: `high`
- Decision: `block`
- Affected resources: 1
- Supporting findings: 1

**Fix:** Use AWS_IAM authorization or remove the downstream sensitive data capability.

Rules:

- `AWS_PUBLIC_LAMBDA_URL_TO_SENSITIVE_DATA`

#### 2. Public admin service reaches sensitive data

- Severity: `critical`
- Confidence: `high`
- Decision: `block`
- Affected resources: 3
- Supporting findings: 3

**Fix:** Limit secret access to the smallest required workload role.

Rules:

- `AWS_PUBLIC_TO_SENSITIVE_DATASTORE`
- `AWS_PUBLIC_TO_SENSITIVE_DATA_PATH`

#### 3. Public workload can read secret

- Severity: `critical`
- Confidence: `high`
- Decision: `block`
- Affected resources: 1
- Supporting findings: 1

**Fix:** Remove public exposure from the workload or scope secret access to a private workload path.

Rules:

- `AWS_PUBLIC_WORKLOAD_READS_SECRET`
... 1 more risk clusters
