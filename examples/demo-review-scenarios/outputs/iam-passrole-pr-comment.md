## ChangeGate: BLOCK

**1 risk cluster** from 5 findings: 5 blocking, 0 warnings, 0 suppressed.

### Decision Reasons

- `MEETS_BLOCK_THRESHOLD` `IAM principal can reach elevated access`: IAM principal can reach elevated access: 5 supporting findings across 2 affected resources

### Risk Clusters

#### 1. IAM principal can reach elevated access

- Severity: `critical`
- Confidence: `high`
- Decision: `block`
- Affected resources: 2
- Supporting findings: 5

**Fix:** Remove broad trust or require tightly scoped conditions and approval for privileged role assumption.

Rules:

- `AWS_IAM_ASSUME_ADMIN_PATH`
- `AWS_IAM_PASSROLE_FUNCTION_ESCALATION`
- `AWS_PASSROLE_WITH_COMPUTE_MUTATION`
- `AWS_ROLE_ASSUME_ADMIN_PATH`
