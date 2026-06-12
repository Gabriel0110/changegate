## ChangeGate: BLOCK

**1 risk cluster** from 3 findings: 2 blocking, 1 warnings, 0 suppressed.

### Decision Reasons

- **IAM principal can reach elevated access:** 3 supporting findings across 2 affected resources

### Risk Clusters

#### 1. IAM principal can reach elevated access

- Severity: `critical`
- Confidence: `high`
- Decision: `block`
- Affected resources: 2
- Supporting findings: 3

**Fix:** Remove broad trust or require tightly scoped conditions and approval for privileged role assumption.

Rules:

- `AWS_IAM_ASSUME_ADMIN_PATH`
- `AWS_IAM_PASSROLE_FUNCTION_ESCALATION`
- `AWS_PASSROLE_WITH_COMPUTE_MUTATION`
